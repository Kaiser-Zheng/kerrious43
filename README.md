# Kerrious43

## Description

Kerrious43 is a small command-line tool that encrypts files and directories using a password-derived key (Argon2id) and ChaCha20-Poly1305 AEAD. It encrypts data in fixed-size chunks, authenticates a header describing format and KDF parameters, and writes per-chunk ciphertext with associated authentication tags.

---

## Installation

### Requirements

* Go toolchain (recommended Go 1.20+).
* Unix-like or Windows environment with terminal for password prompt.

### Build

```bash
git clone git@github.com:Kaiser-Zheng/kerrious43.git
cd kerrious43
go build -o kerrious43 .
```

### Quick verification

```bash
./kerrious43 -h
```

---

## Usage

### Flags

* `-e` : encryption mode (mutually exclusive with `-d`).
* `-d` : decryption mode.
* `-in string` : input file or directory (required).
* `-workers int` : number of concurrent workers (default: min(2, CPU)).
* `-y` : assume yes for overwrite confirmation.

### Examples

**Encrypt a directory**

```bash
./kerrious43 -e -in /path/to/dir/
# outputs to ./encrypted_files/ preserving relative layout, with .enc suffix
```

**Decrypt a single file**

```bash
./kerrious43 -d -in /path/to/file.txt.enc
# outputs to ./decrypted_files/file.txt
```

### Password entry

* The program requires a TTY for password entry; it will abort if stdin is not a terminal.
* Encryption prompts for confirmation; decryption requests a single password entry.

---

## Security Consideration

### File format summary

* **Header (73 bytes)**: `magic ("SECFILE") | version | argon2 t | argon2 m (KiB) | argon2 p | chunk size | salt (32B) | base nonce (12B) | original file size (8B)`.
* **Per chunk**: `4-byte LE plaintext length | ciphertext (len + 16B tag)`.
* **Footer**: `1-byte flag (0xFF) | 16-byte tag` authenticating the header, total chunk count, and declared file size.
* **Associated data (AAD)**:

  * For each chunk: `header || chunkIndex || chunkLength`.
  * For the footer: `header || totalChunkCount || fileSize`.

### Recommendations

* Use a strong, unique password (consider a password manager).
* Keep backups and test decrypting before deleting original plaintext.
* Make KDF caps configurable if your deployment needs different memory/time trade-offs.

---

## Contributing

* Fork the repository, implement changes on a feature branch, open a pull request with a clear security rationale for changes.
* Include tests that cover parsing, decryption with tampered headers/lengths/footer, and KDF parameter edge cases.
