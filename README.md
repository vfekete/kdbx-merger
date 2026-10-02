# kdbx-merger-cli

`merge-kdbx` merges several KeePass databases (`.kdbx`) into one new database without losing
any password. The folder structure is kept, and nothing is ever overwritten.

## How it merges

- The first input file is copied 1:1 into the output. Each following file is merged into it,
  in command line order.
- Folders with the same path are combined into one, never duplicated.
- An item whose title already exists in the same folder is added as `title - 1`, `title - 2`,
  …, with a `source: <file>` line in its notes:

  ```
  Folder1/Folder2/
    item        (from file1.kdbx)
    item - 1    (from some/path2/file2.kdbx, note: "source: some/path2/file2.kdbx")
  ```
- All item properties are kept: passwords, custom fields, attachments, history, tags, icons,
  creation and expiry times (expired items included).
- Identical attachments are stored once, and their entries get a note listing every input
  file the attachment was found in.
- Names must be identical to match. Names that only look alike (letter case, extra spaces,
  differently encoded accents) are kept separate and reported during the merge.
- Input files are opened read-only. Passwords are kept only in memory and wiped as soon as
  they are no longer needed.

## Requirements

- Linux
- [uv](https://docs.astral.sh/uv/). It installs the Python dependencies automatically on the
  first run.
- `secret-tool` (package `libsecret-tools`), only if you use the `secret-tool` options

## Usage

```bash
./merge-kdbx -i file1.kdbx some/path/file2.kdbx -ip user -o merged.kdbx -p some_password
```

| Option | Meaning |
| --- | --- |
| `-i FILE FILE …` | Input files, at least two, in priority order |
| `-ip user` | Type input passwords (default). A password that worked is tried on the following files first, so a shared password is typed only once. |
| `-ip secret-tool` | Read input passwords from the system keyring (see below) |
| `-o FILE` | Output file. It must not exist yet. |
| `-p PASSWORD` | Output password on the command line (visible in `ps` and shell history) |
| `-ps SPEC` | Output password from `secret-tool`: an item label, or `attr=value[,attr=value]` |
| *(neither `-p` nor `-ps`)* | Output password is typed twice at a prompt |
| `-f`, `--force` | Overwrite an existing output file (never an input file) |
| `-v` | List renamed duplicates and combined folders |

Run `./merge-kdbx --help` for the full description.

### Input passwords from secret-tool

Store each input file's password under the attribute `service = "<PIN>-<absolute path>"`,
where the PIN is a number you choose:

```bash
secret-tool store --label="kdbx file1" service "1234-/home/me/file1.kdbx"
```

With `-ip secret-tool`, the script asks once for the PIN and looks up each file's password.
If a file has no entry, or its stored password doesn't work, the passwords of the previous
files are tried. If none works, you can type the password or cancel the merge.

## Tests

```bash
./tests/test_merge_kdbx.py
```

The tests build temporary mock databases with nested folders, duplicates, attachments,
history, expiry dates and names in many scripts. They then merge them and check the result.

## License

See [LICENSE](LICENSE).
