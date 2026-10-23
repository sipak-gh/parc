# parc

`parc` (short for **p**ublic **arc**hiver) encrypts files **and their names** using your SSH key, so you can store
them in a public place (a git repo, a bucket, a web server) without revealing
either the contents or what the files are called. Only the holder of the
matching private key can read a file or even tell what it is.

It is built on [age](https://github.com/FiloSottile/age) and works with
**ed25519 SSH keys only**.

```
secret-notes.txt  ->  5tzxlf34cn5p4zrs6we7hr...(231 chars).parc
```

## Install

```sh
go install github.com/sipak-gh/parc/cmd/parc@latest
# or, from a checkout:
go build -o parc ./cmd/parc
```

## Usage

```sh
parc enc <PATH>              # encrypt a file and its name
parc dec <PATH>              # decrypt a file and restore its name
parc inspect <PATH|URL>      # show the original name only
```

| Flag | Applies to | Meaning |
|------|-----------|---------|
| `-o, --out-dir DIR` | enc, dec | Write output to `DIR` (default: current directory). |
| `--key PATH` | all | ed25519 SSH key to use (default `~/.ssh/id_ed25519`). |
| `-r, --recipient KEY` | enc | Encrypt to a public key (`"ssh-ed25519 AAAA..."` or a `.pub` file) instead of your own. |
| `-R, --replace` | enc, dec | Delete the source file afterwards, and overwrite existing output. |
| `--follow` | inspect | For URLs, follow redirects and `Content-Disposition` to find the name. |

Flags may come before or after the path; use `--` for paths starting with `-`.

### Examples

```sh
parc enc taxes-2025.pdf -o public/          # -> public/<random-looking>.parc
parc inspect public/<random-looking>.parc   # -> taxes-2025.pdf
parc dec -o restored/ public/<random-looking>.parc   # -> restored/taxes-2025.pdf

# What is this remote file?
parc inspect https://example.com/files/<random-looking>.parc
parc inspect --follow https://example.com/download?id=42   # resolves redirects

# Encrypt for someone else using only their public key
parc enc -r "ssh-ed25519 AAAA... alice" report.docx
```

Without `-R`, existing outputs are never overwritten and sources are never
deleted. A failed run leaves no partial output and keeps the source.

## Try it

`data/` holds encrypted copies of this program's own source files, plus a
deliberately public example key, so you can try `parc` without setting anything
up. Clone the repo (or just download `data/parc_example_key`), then ask what a
file on GitHub really is. The name is read straight from the URL, so no
download is needed:

```sh
git clone https://github.com/sipak-gh/parc && cd parc

parc inspect --key data/parc_example_key \
  https://github.com/sipak-gh/parc/raw/master/data/6xywvwawtxwiqh6cln5cfsaecg76kdtlroj5bqe33quh4unzrnrtefsmdxuip46ibi7xpx3ojnqprxhdrtni2ayielaqkzrehblx5nbvbj64b4ri3ve735eg4ajgqku35qm47thcmrptbog54nwgwjozeivkqaseqsndvexmfgfs5ow52nyl3ycvgi6kvv42nu7t4b2zwob5deptfgj2ordphtqarqegwrjbclq.parc
# -> go.mod

parc inspect --key data/parc_example_key \
  https://github.com/sipak-gh/parc/raw/master/data/r23trvyvrhi2luzvrc3gu2bixi6dqzy4k3ht3qndswrrgc7jvet75gslvnwlpryf5rcgl2g6zjrllylnwflufyhgb7opbbvuok5gjljcmuuv3z4htae3nwyk647pnvlhpnqnorpl34hwmvy6p34a47ae5xm6fh3sonxt7zuswulv4bpffql3dphj6ni4nphxaurd2msqkw4yuukfpsshoeqgzu4vmxc5tjlzmla.parc
# -> keys.go
```

Decrypt a file (fetch the raw file, then `dec`):

```sh
curl -LO https://github.com/sipak-gh/parc/raw/master/data/6xywvwawtxwiqh6cln5cfsaecg76kdtlroj5bqe33quh4unzrnrtefsmdxuip46ibi7xpx3ojnqprxhdrtni2ayielaqkzrehblx5nbvbj64b4ri3ve735eg4ajgqku35qm47thcmrptbog54nwgwjozeivkqaseqsndvexmfgfs5ow52nyl3ycvgi6kvv42nu7t4b2zwob5deptfgj2ordphtqarqegwrjbclq.parc
parc dec --key data/parc_example_key -o out 6xywvwawtxwiqh6cln5cfsaecg76kdtlroj5bqe33quh4unzrnrtefsmdxuip46ibi7xpx3ojnqprxhdrtni2ayielaqkzrehblx5nbvbj64b4ri3ve735eg4ajgqku35qm47thcmrptbog54nwgwjozeivkqaseqsndvexmfgfs5ow52nyl3ycvgi6kvv42nu7t4b2zwob5deptfgj2ordphtqarqegwrjbclq.parc
# -> out/go.mod
```

Or list everything in the folder:

```sh
for f in data/*.parc; do parc inspect --key data/parc_example_key "$f"; done
```

See [`data/README.md`](data/README.md). **Never use the example key for real data.**

## How it works

- **Contents:** standard age encryption to your SSH public key; decrypting
  needs the private key.
- **Names:** the name is padded to 96 bytes and encrypted to your public key
  (ephemeral X25519 + ChaCha20-Poly1305), then base32-encoded into the filename.
  - Every encrypted name is the same length (236 characters including `.parc`),
    so the length reveals nothing.
  - A fresh ephemeral key is used each time, so encrypting the same name twice
    gives different results.
  - Because only the public key is needed, `enc` never asks for your
    passphrase when `<key>.pub` exists, and others can encrypt files for you.
  - Anything that reads the filename (a URL, a directory listing) can `inspect`
    it without downloading the file.

## Limitations

- **ed25519 only.** RSA and ECDSA keys are rejected: an RSA-encrypted name
  would not fit in a filename.
- **Names are limited to 95 bytes** (a filename longer than that is rejected).
- **Sizes and timing are not hidden:** file size is visible, and the same
  content encrypted twice produces different files, so duplicates can't be
  detected from outside.
- **Anyone with your public key can create `.parc` files for you.** Encryption
  is not authentication; `parc` does not prove who made a file.
- If your key has a passphrase, `dec` and `inspect` prompt for it on the
  terminal.

## Development

```sh
go test ./...                                              # unit + CLI tests
go test ./cmd/parc -run '^$' -fuzz FuzzFileRoundTrip -fuzztime 1m   # fuzzers: see parc_test.go
```

Code lives in `cmd/parc/`: `main.go` (CLI and file handling), `keys.go` (SSH
key loading), `names.go` (name encryption), `remote.go` (URL inspection).

## License

[0BSD](LICENSE) (BSD Zero Clause): do whatever you like, no attribution required.
