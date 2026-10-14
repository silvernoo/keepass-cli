# kpass

`kpass` is a focused Rust CLI for reading KeePass KDBX databases. The first version is intentionally read-only: it provides safe inspection and search before adding commands that can mutate a password vault.

## Usage

With no subcommand, `kpass` starts an interactive browser. It asks for a search term, lets you select an entry, and displays all fields including the password so you can copy it manually. The main menu also provides `Add new entry`; it asks for a group, the standard KeePass fields, optional tags, and saves the database by default.

The database defaults to `data.kdbx` in the current directory.

```text
./target/release/kpass
./target/release/kpass --database /path/to/vault.kdbx
./target/release/kpass add
```

The interactive browser intentionally requires a terminal password prompt. Use the explicit subcommands below for scripts and non-interactive usage.

```text
cargo run -- info
cargo run -- list
cargo run -- search github
cargo run -- show github
cargo run -- show github --reveal
cargo run -- add
```

Use another database or a keyfile with global options:

```text
cargo run -- --database /path/to/vault.kdbx list
cargo run -- --database vault.kdbx --key-file vault.key list
cargo run -- --database key-only.kdbx --key-file vault.key --no-password list
printf '%s\n' "$KDBX_PASSWORD" | cargo run -- --password-stdin list
```

The interactive browser displays the selected entry's protected fields by design, so run it only where the terminal output is private. Passwords are never accepted as command-line arguments, so they do not end up in shell history or the process list.

## Development

```text
cargo fmt --check
cargo test
cargo check
```

`info` only parses the public KDBX header and is useful for checking a file without unlocking it.


KeePass entries use a map of string fields rather than a fixed database column layout. The five conventional fields are stored with these exact names: `Title`, `UserName`, `Password`, `URL`, and `Notes`. Custom string fields are valid KDBX data and are preserved.

Saving currently targets KDBX 4.x. KDBX 4.0 files are read successfully and are upgraded to KDBX 4.1 when saved, because the current Rust writer only emits KDBX 4.1. Entry data is preserved during this minor-version upgrade.


