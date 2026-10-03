# WinBox CDB Viewer

A standalone Rust / eframe application for Linux and Windows. Open a WinBox
address book, inspect saved accounts in a table, and export all data as TXT or
JSON. No WinBox installation or network connection is required.

See `VERIFICATION.txt` for the validation scope and platform limitations.

## Build and run

Run these commands in the project directory with Rust 1.95 or newer:

```sh
cargo build --release --locked
cargo run --release --locked --bin winbox-cdb
```

The executable is `target/release/winbox-cdb` on Linux or
`target/release/winbox-cdb.exe` on Windows. On Windows, install the MSVC Rust
toolchain and Visual Studio Build Tools with Desktop development with C++.

Debian/Ubuntu build dependencies:

```sh
sudo apt install build-essential pkg-config libx11-dev libxkbcommon-dev libwayland-dev libgl1-mesa-dev
```

The Linux GUI requires X11 or Wayland and an OpenGL driver. The Windows GUI
uses wgpu (Direct3D/Vulkan), allowing it to run with the Windows software
adapter when a VM graphics driver does not provide modern OpenGL.
Linux file dialogs use XDG Desktop Portal, usually provided by the desktop
environment; install
`xdg-desktop-portal` and a suitable backend if necessary. Windows uses native
dialogs. On Alpine/musl, build with dynamic libc:

```sh
RUSTFLAGS="-C target-feature=-crt-static" cargo build --release --locked
```

Build Linux executables on the target distribution or a compatible system.
An Alpine/musl build is not a universal glibc executable. The included
`.github/workflows/build.yml` builds and tests on Ubuntu and Windows when this
project is used as a repository.

The original application artwork is bundled in `assets/icon.png`. It is
embedded in the GUI window. Windows builds also convert it to an ICO resource
and embed it in the executable; no external icon file is needed at runtime.

## Use

1. Click **Open** to load the default WinBox address book, or **Browse…** to
   select a file. The selected file opens immediately. The **WinBox path**
   button restores the platform default. Portable and Wine installations may
   require selecting their address book manually.
2. Encrypted books prompt for a password. Empty passwords are allowed and
   whitespace is preserved. **Password from file…** reads raw bytes and removes
   one trailing LF or CRLF. Failed attempts can be retried or cancelled.
3. The table shows address, user, password, group, comments, RoMON agent,
   workspace, the saved-password flag, and ID. Passwords are initially hidden;
   **Show passwords** reveals them. Search covers the other columns.
4. Select a row to inspect every field in original order, including unknown
   IDs, nested messages, and duplicate fields.
5. **Export TXT** and **Export JSON** export all records and plaintext passwords,
   regardless of the search filter or password visibility toggle.

The application never modifies the input book and refuses to overwrite an
existing export. New exports use mode 0600 on Unix and inherited directory
ACLs on Windows. Loaded documents and passwords are not persisted in settings
or sent over the network. **Close book** removes the loaded document from view.
Application labels and messages are English; user data is displayed unchanged.
Native dialogs and operating-system error descriptions may follow system locale.

## Supported format

- Plain CDB magic `0xC01DF00D`.
- Encrypted CDB magic `0x4011F00D`: RC4-drop768, SHA1(salt32 || password).
- All 14 M2 types, nested messages, short and wide lengths, and bit26.
- Unknown fields, duplicate fields, original headers, and offsets.
- UTF-8 strings; binary and invalid UTF-8 values represented as hex objects.
- Limits: 64 MiB per file, 1 MiB per record, 100,000 records; per record,
  200,000 fields, 1,000,000 array elements, and nesting depth 32.

JSON preserves the complete diagnostic structure. TXT provides a readable
field listing. CDB encryption has no MAC: successful parsing is not
cryptographic authentication. Unsupported magic values are rejected.
Compatibility with every historical WinBox version is not guaranteed.

## Command-line export

The optional console exporter can be built without GUI dependencies:

```sh
cargo run --no-default-features --bin cdb-dump -- input.cdb --format json -o new.json
cargo run --no-default-features --bin cdb-dump -- input.cdb --password-file password.txt --format text -o new.txt
```

Encrypted input requires `--password-file` in console mode. Without `-o`, output
is written to stdout.

## Verification

```sh
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
```

All fixtures in `tests/fixtures` are synthetic. Tests cover reference JSON/TXT
output, all field types, encryption with a Unicode password, duplicate fields,
bit26, offsets, empty books, malformed input, resource limits, export file
protection, and GUI password retry and table rendering.

`python3 tests/generate_fixtures.py` regenerates the synthetic CDB inputs using
only the standard library. JSON/TXT reference outputs are maintained separately
and must be reviewed when fixture data changes. Python is not required to build,
test, or run the application. Every project-specific asset and test input is
included in this directory.
