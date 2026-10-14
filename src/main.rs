use std::{
    fs::File,
    io::{self},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use comfy_table::{presets::UTF8_FULL, Table};
use dialoguer::{Confirm, Input, Password, Select};
use keepass::{
    config::DatabaseVersion,
    db::{fields, Database, EntryId, GroupId, GroupRef},
    DatabaseKey,
};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

const DEFAULT_DATABASE: &str = "data.kdbx";

#[derive(Debug, Parser)]
#[command(
    name = "kpass",
    version,
    about = "A focused CLI for KeePass KDBX databases",
    long_about = "Browse KeePass entries interactively, or inspect and search them with subcommands.",
    color = clap::ColorChoice::Auto,
)]
struct Cli {
    #[command(flatten)]
    database: DatabaseArgs,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Args)]
struct DatabaseArgs {
    /// KDBX database path
    #[arg(short, long, global = true, env = "KDBX_DATABASE", default_value = DEFAULT_DATABASE)]
    database: PathBuf,

    /// KeePass keyfile path
    #[arg(short = 'k', long, global = true, env = "KDBX_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Read the master password from stdin instead of prompting
    #[arg(long, global = true, conflicts_with = "no_password")]
    password_stdin: bool,

    /// Unlock with only the keyfile, without asking for a master password
    #[arg(long, global = true, conflicts_with = "password_stdin")]
    no_password: bool,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start the interactive browser
    Interactive,

    /// Show database metadata without unlocking it
    Info,

    /// List entries, optionally filtered by a query
    List {
        /// Match title, username, URL, or group path
        query: Option<String>,
    },

    /// Search entries by title, username, URL, or group path
    Search {
        /// Text to search for
        query: String,
    },

    /// Add a new entry and save it
    Add,

    /// Show the fields of one entry
    Show(ShowArgs),
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// Entry title, partial text, or UUID
    selector: String,

    /// Reveal passwords, OTPs, and other protected values
    #[arg(long)]
    reveal: bool,
}

#[derive(Debug)]
struct EntrySummary {
    id: EntryId,
    title: String,
    username: String,
    url: String,
    group: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        None => run_interactive(&cli.database),
        Some(Command::Interactive) => run_interactive(&cli.database),
        Some(Command::Info) => print_info(&cli.database.database),
        Some(Command::List { query }) => {
            let database = open_database(&cli.database)?;
            let entries = collect_entries(&database);
            print_entry_table(filter_entries(&entries, query.as_deref()))
        }
        Some(Command::Search { query }) => {
            let database = open_database(&cli.database)?;
            let entries = collect_entries(&database);
            print_entry_table(filter_entries(&entries, Some(&query)))
        }
        Some(Command::Add) => {
            let (mut database, key) = open_database_with_key(&cli.database)?;
            add_entry_interactive(&mut database, &key, &cli.database.database)
        }
        Some(Command::Show(args)) => {
            let database = open_database(&cli.database)?;
            show_entry(&database, &args.selector, args.reveal)
        }
    }
}

fn run_interactive(args: &DatabaseArgs) -> Result<()> {
    if args.password_stdin {
        bail!("interactive mode requires a terminal password prompt; remove --password-stdin");
    }

    let (mut database, key) = open_database_with_key(args)?;

    println!("kpass interactive");
    println!("Search entries, add new passwords, and save changes safely.");
    println!();

    loop {
        let action = Select::new()
            .with_prompt("What would you like to do?")
            .items(["Search entries", "Add new entry", "Exit"])
            .default(0)
            .interact()
            .context("interactive action cancelled")?;

        match action {
            0 => search_interactive(&database)?,
            1 => add_entry_interactive(&mut database, &key, &args.database)?,
            _ => break,
        }
    }

    Ok(())
}

fn search_interactive(database: &Database) -> Result<()> {
    loop {
        let entries = collect_entries(database);
        let query = Input::<String>::new()
            .with_prompt("Search (empty shows all entries, q goes back)")
            .allow_empty(true)
            .interact_text()
            .context("interactive search cancelled")?;

        if query.eq_ignore_ascii_case("q") {
            return Ok(());
        }

        let matches = filter_entries(&entries, Some(&query));
        if matches.is_empty() {
            println!("No matching entries. Try another search.");
            println!();
            continue;
        }

        let selected = choose_entry(&matches)?;
        print_entry_details(database, selected, true)?;
        println!();

        let action = Select::new()
            .with_prompt("What next?")
            .items(["Search again", "Back to main menu"])
            .default(0)
            .interact()
            .context("interactive action cancelled")?;
        if action == 1 {
            return Ok(());
        }
        println!();
    }
}

fn print_info(path: &Path) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("cannot read database metadata: {}", path.display()))?;
    let mut file =
        File::open(path).with_context(|| format!("cannot open database: {}", path.display()))?;
    let version = Database::get_version(&mut file).context("cannot parse the KDBX file header")?;

    println!("Database  {}", path.display());
    println!("Format    {}", format_version(version));
    println!("Size      {} bytes", metadata.len());
    println!();
    println!("The header is valid. Unlocking is only needed for list, search, and show.");
    Ok(())
}

fn format_version(version: DatabaseVersion) -> String {
    match version {
        DatabaseVersion::KDB(_) => "KDB 1.x".to_owned(),
        DatabaseVersion::KDB2(_) => "KDB 2.x (unsupported)".to_owned(),
        DatabaseVersion::KDB3(_) => "KDBX 3.x".to_owned(),
        DatabaseVersion::KDB4(minor) => format!("KDBX 4.x (minor {minor})"),
    }
}

fn open_database(args: &DatabaseArgs) -> Result<Database> {
    open_database_with_key(args).map(|(database, _)| database)
}

fn open_database_with_key(args: &DatabaseArgs) -> Result<(Database, DatabaseKey)> {
    let can_retry = !args.password_stdin && !args.no_password;
    let max_attempts = if can_retry { 3 } else { 1 };
    let mut last_error = None;

    for attempt in 0..max_attempts {
        let mut file = File::open(&args.database)
            .with_context(|| format!("cannot open database: {}", args.database.display()))?;
        let key = read_database_key(args)?;

        match Database::open(&mut file, key.clone()) {
            Ok(database) => return Ok((database, key)),
            Err(error) if attempt + 1 < max_attempts => {
                eprintln!(
                    "Unable to unlock the database. Try again ({}/{}).",
                    attempt + 1,
                    max_attempts
                );
                last_error = Some(error);
            }
            Err(error) => {
                last_error = Some(error);
                break;
            }
        }
    }

    let error = last_error.expect("at least one database unlock attempt must run");
    Err(anyhow::anyhow!(
        "cannot unlock {}: {error}\nCheck the master password and keyfile.",
        args.database.display()
    ))
}

fn read_database_key(args: &DatabaseArgs) -> Result<DatabaseKey> {
    let mut key = DatabaseKey::new();

    if let Some(path) = &args.key_file {
        let mut keyfile =
            File::open(path).with_context(|| format!("cannot open keyfile: {}", path.display()))?;
        key = key
            .with_keyfile(&mut keyfile)
            .with_context(|| format!("cannot read keyfile: {}", path.display()))?;
    }

    if !args.no_password {
        let password = read_password(args.password_stdin)?;
        key = key.with_password(&password);
    }

    if key.is_empty() {
        bail!("no credentials supplied; provide a password or --key-file");
    }

    Ok(key)
}

fn read_password(from_stdin: bool) -> Result<Zeroizing<String>> {
    if from_stdin {
        let mut password = Zeroizing::new(String::new());
        io::stdin()
            .read_line(&mut password)
            .context("cannot read password from stdin")?;
        while password.ends_with(['\n', '\r']) {
            password.pop();
        }
        return Ok(password);
    }

    Password::new()
        .with_prompt("Master password")
        .interact()
        .map(Zeroizing::new)
        .context("cannot read master password")
}

#[derive(Debug)]
struct GroupSummary {
    id: GroupId,
    path: String,
}

fn collect_groups(database: &Database) -> Vec<GroupSummary> {
    let mut groups = Vec::new();
    collect_group_summaries(database.root(), Vec::new(), &mut groups);
    groups
}

fn collect_group_summaries(
    group: GroupRef<'_>,
    mut path: Vec<String>,
    groups: &mut Vec<GroupSummary>,
) {
    if group.parent().is_some() && !group.name.is_empty() {
        path.push(group.name.clone());
    }
    let group_path = if path.is_empty() {
        "(root)".to_owned()
    } else {
        path.join(" / ")
    };
    groups.push(GroupSummary {
        id: group.id(),
        path: group_path,
    });

    for child in group.groups() {
        collect_group_summaries(child, path.clone(), groups);
    }
}

fn add_entry_interactive(database: &mut Database, key: &DatabaseKey, path: &Path) -> Result<()> {
    let groups = collect_groups(database);
    let group_labels: Vec<&str> = groups.iter().map(|group| group.path.as_str()).collect();
    let group_index = Select::new()
        .with_prompt("Save entry in group")
        .items(&group_labels)
        .default(0)
        .interact()
        .context("group selection cancelled")?;
    let group_id = groups[group_index].id;

    let title = Input::<String>::new()
        .with_prompt("Title")
        .interact_text()
        .context("could not read entry title")?;
    let username = Input::<String>::new()
        .with_prompt("UserName")
        .allow_empty(true)
        .interact_text()
        .context("could not read entry username")?;
    let password = Password::new()
        .with_prompt("Password")
        .allow_empty_password(true)
        .interact()
        .map(Zeroizing::new)
        .context("could not read entry password")?;
    let url = Input::<String>::new()
        .with_prompt("URL")
        .allow_empty(true)
        .interact_text()
        .context("could not read entry URL")?;
    let notes = Input::<String>::new()
        .with_prompt("Notes")
        .allow_empty(true)
        .interact_text()
        .context("could not read entry notes")?;
    let tags = Input::<String>::new()
        .with_prompt("Tags (comma separated, optional)")
        .allow_empty(true)
        .interact_text()
        .context("could not read entry tags")?;
    let tags: Vec<String> = tags
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_owned)
        .collect();

    let protection = database.meta.memory_protection.as_ref().cloned().unwrap_or(
        keepass::db::MemoryProtection {
            protect_title: false,
            protect_username: false,
            protect_password: true,
            protect_url: false,
            protect_notes: false,
        },
    );

    {
        let mut group = database
            .group_mut(group_id)
            .context("selected group is no longer available")?;
        let mut entry = group.add_entry();
        set_entry_value(&mut entry, fields::TITLE, title, protection.protect_title);
        set_entry_value(
            &mut entry,
            fields::USERNAME,
            username,
            protection.protect_username,
        );
        set_entry_value(&mut entry, fields::PASSWORD, password.to_string(), true);
        set_entry_value(&mut entry, fields::URL, url, protection.protect_url);
        set_entry_value(&mut entry, fields::NOTES, notes, protection.protect_notes);
        entry.tags = tags;
    }

    println!("Entry added. Password fields are stored as protected values.");
    let save = Confirm::new()
        .with_prompt("Save changes to the database now?")
        .default(true)
        .interact()
        .context("save confirmation cancelled")?;
    if save {
        save_database_atomic(database, key, path)?;
        println!("Saved {}", path.display());
    } else {
        println!("Changes are only in memory and will be lost when the program exits.");
    }

    Ok(())
}

fn set_entry_value(
    entry: &mut keepass::db::EntryMut<'_>,
    field: &str,
    value: String,
    protected: bool,
) {
    if protected {
        entry.set_protected(field, value);
    } else {
        entry.set_unprotected(field, value);
    }
}

fn save_database_atomic(database: &mut Database, key: &DatabaseKey, path: &Path) -> Result<()> {
    match database.config.version {
        DatabaseVersion::KDB4(0) => {
            // keepass 0.15's writer emits KDBX 4.1 and rejects the older 4.0 minor version.
            database.config.version = DatabaseVersion::KDB4(1);
        }
        DatabaseVersion::KDB4(1) => {}
        DatabaseVersion::KDB4(minor) => {
            bail!("cannot save unsupported KDBX 4.x minor version {minor}");
        }
        _ => bail!("saving is currently supported only for KDBX 4.x databases"),
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = NamedTempFile::new_in(parent)
        .with_context(|| format!("cannot create a temporary file near {}", path.display()))?;
    database
        .save(temporary.as_file_mut(), key.clone())
        .with_context(|| format!("cannot serialize database for {}", path.display()))?;
    temporary
        .as_file_mut()
        .sync_all()
        .context("cannot flush the temporary database file")?;
    temporary
        .persist(path)
        .map_err(|error| anyhow::anyhow!("cannot replace {}: {}", path.display(), error.error))?;
    Ok(())
}

fn collect_entries(database: &Database) -> Vec<EntrySummary> {
    let mut entries = Vec::new();
    collect_group(database.root(), Vec::new(), &mut entries);
    entries
}

fn collect_group(group: GroupRef<'_>, mut path: Vec<String>, entries: &mut Vec<EntrySummary>) {
    if group.parent().is_some() && !group.name.is_empty() {
        path.push(group.name.clone());
    }
    let group_path = if path.is_empty() {
        "(root)".to_owned()
    } else {
        path.join(" / ")
    };

    for entry in group.entries() {
        entries.push(EntrySummary {
            id: entry.id(),
            title: entry
                .get_title()
                .filter(|value| !value.is_empty())
                .unwrap_or("(untitled)")
                .to_owned(),
            username: entry.get_username().unwrap_or_default().to_owned(),
            url: entry.get_url().unwrap_or_default().to_owned(),
            group: group_path.clone(),
        });
    }

    for child in group.groups() {
        collect_group(child, path.clone(), entries);
    }
}

fn filter_entries<'a>(entries: &'a [EntrySummary], query: Option<&str>) -> Vec<&'a EntrySummary> {
    let Some(query) = query.filter(|query| !query.trim().is_empty()) else {
        return entries.iter().collect();
    };

    let query = query.to_lowercase();
    entries
        .iter()
        .filter(|entry| {
            entry.title.to_lowercase().contains(&query)
                || entry.username.to_lowercase().contains(&query)
                || entry.url.to_lowercase().contains(&query)
                || entry.group.to_lowercase().contains(&query)
                || entry.id.to_string().eq_ignore_ascii_case(query.trim())
        })
        .collect()
}

fn print_entry_table(entries: Vec<&EntrySummary>) -> Result<()> {
    if entries.is_empty() {
        bail!("no matching entries");
    }

    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(["#", "Group", "Title", "Username", "URL"]);

    for (index, entry) in entries.iter().enumerate() {
        table.add_row([
            (index + 1).to_string(),
            entry.group.clone(),
            entry.title.clone(),
            entry.username.clone(),
            entry.url.clone(),
        ]);
    }

    println!("{table}");
    println!();
    println!(
        "{} entr{}",
        entries.len(),
        if entries.len() == 1 { "y" } else { "ies" }
    );
    Ok(())
}

fn show_entry(database: &Database, selector: &str, reveal: bool) -> Result<()> {
    let entries = collect_entries(database);
    let matches = filter_entries(&entries, Some(selector));
    let selected = match matches.as_slice() {
        [] => bail!("no entry matches {selector:?}"),
        [entry] => *entry,
        many => choose_entry(many)?,
    };

    print_entry_details(database, selected, reveal)
}

fn print_entry_details(database: &Database, selected: &EntrySummary, reveal: bool) -> Result<()> {
    let entry = database
        .entry(selected.id)
        .context("the selected entry is no longer available")?;

    println!("{}", selected.title);
    println!("Group     {}", selected.group);
    println!("ID        {}", selected.id);
    println!();

    let mut fields_to_print: Vec<(&str, &str)> = entry
        .fields
        .keys()
        .filter_map(|name| {
            let raw_value = entry.fields.get(name)?;
            let value = entry.get(name)?;
            let value = if reveal || !(raw_value.is_protected() || is_sensitive_field(name)) {
                value
            } else {
                "********"
            };
            Some((name.as_str(), value))
        })
        .collect();
    fields_to_print.sort_by(|left, right| field_order(left.0).cmp(&field_order(right.0)));

    let mut table = Table::new();
    table.load_style(UTF8_FULL);
    table.set_header(["Field", "Value"]);
    for (name, value) in fields_to_print {
        table.add_row([name, value]);
    }
    println!("{table}");
    if !entry.tags.is_empty() {
        println!("Tags      {}", entry.tags.join(", "));
    }
    if let Some(override_url) = &entry.override_url {
        println!("URL override  {override_url}");
    }
    if entry.autotype.is_some() {
        println!("Auto-Type configured");
    }
    let attachment_count = entry.attachments().count();
    if attachment_count > 0 {
        println!("Attachments  {attachment_count}");
    }
    if let Some(history) = &entry.history {
        let history_count = history.get_entries().len();
        if history_count > 0 {
            println!("History      {history_count} previous version(s)");
        }
    }
    Ok(())
}

fn field_order(name: &str) -> (u8, &str) {
    let rank = match name {
        fields::USERNAME => 0,
        fields::PASSWORD => 1,
        fields::TITLE => 2,
        fields::URL => 3,
        fields::NOTES => 4,
        _ => 5,
    };
    (rank, name)
}

fn choose_entry<'a>(entries: &'a [&'a EntrySummary]) -> Result<&'a EntrySummary> {
    let labels: Vec<String> = entries
        .iter()
        .map(|entry| format!("{}  ·  {}  ·  {}", entry.title, entry.username, entry.group))
        .collect();
    let selected = Select::new()
        .with_prompt("Multiple entries matched; choose one")
        .items(&labels)
        .default(0)
        .interact()
        .context("entry selection cancelled")?;
    Ok(entries[selected])
}

fn is_sensitive_field(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "password" | "otp" | "totp" | "secret" | "private key"
    )
}

#[cfg(test)]
mod tests {
    use super::{filter_entries, save_database_atomic, EntrySummary};
    use keepass::db::EntryId;
    use keepass::{config::DatabaseVersion, db::fields, Database, DatabaseKey};

    fn entry(title: &str, group: &str) -> EntrySummary {
        EntrySummary {
            id: EntryId::new(),
            title: title.to_owned(),
            username: "alice".to_owned(),
            url: "https://example.test".to_owned(),
            group: group.to_owned(),
        }
    }

    #[test]
    fn filters_across_human_facing_fields() {
        let entries = vec![entry("GitHub", "Work / Code"), entry("Bank", "Personal")];
        assert_eq!(filter_entries(&entries, Some("code")).len(), 1);
        assert_eq!(filter_entries(&entries, Some("ALICE")).len(), 2);
        assert_eq!(filter_entries(&entries, Some("missing")).len(), 0);
    }

    #[test]
    fn saves_and_reopens_a_new_entry() {
        let mut database = Database::new();
        database.root_mut().add_entry().edit(|entry| {
            entry.set_unprotected(fields::TITLE, "Saved entry");
            entry.set_unprotected(fields::USERNAME, "alice");
            entry.set_protected(fields::PASSWORD, "secret");
            entry.set_unprotected(fields::URL, "https://example.test");
            entry.set_unprotected(fields::NOTES, "notes");
        });

        database.config.version = DatabaseVersion::KDB4(0);

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("vault.kdbx");
        let key = DatabaseKey::new().with_password("test-password");
        save_database_atomic(&mut database, &key, &path).unwrap();
        save_database_atomic(&mut database, &key, &path).unwrap();

        let mut header = std::fs::File::open(&path).unwrap();
        assert_eq!(
            Database::get_version(&mut header).unwrap(),
            DatabaseVersion::KDB4(1)
        );

        let mut file = std::fs::File::open(&path).unwrap();
        let reopened = Database::open(&mut file, key).unwrap();
        let root = reopened.root();
        let entry = root.entries().next().unwrap();
        assert_eq!(entry.get_title(), Some("Saved entry"));
        assert_eq!(entry.get_username(), Some("alice"));
        assert_eq!(entry.get_password(), Some("secret"));
        assert_eq!(entry.get_url(), Some("https://example.test"));
        assert_eq!(entry.get(fields::NOTES), Some("notes"));
    }
}
