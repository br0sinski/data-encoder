# de-encryptor

A simple data en/-decryptor with a little password generator - written in C for educational purposes

## CI Status

You can check the [GitHub Actions](https://github.com/br0sinski/de-encryptor/actions) page to see if the build and tests run successfully on both **Linux** and **Windows**.
The GitHub Workflow file can be found [here](https://github.com/br0sinski/de-encryptor/blob/main/.github/workflows/action.yml)

## Build

```sh
make
```

## Usage

### Generate a secure password

```sh
./encoder generate [length]
```
- `[length]` is optional (default: 24).

**Example:**
```sh
./encoder generate 32
```

---

### Encrypt a file

```sh
./encoder encrypt <input_file> <output_file> <password>
```

**Example:**
```sh
./encoder encrypt secret.txt secret.enc password
```

---

### Decrypt a file

```sh
./encoder decrypt <input_file> <output_file> <password>
```

**Example:**
```sh
./encoder decrypt secret.enc secret_decrypted.txt password
```

---

## Run Unit Tests

```sh
make test
```

---

## Notes

- Only standard C libraries are used.
- AES-128 in CBC mode is used for encryption.
- Passwords are never stored in plaintext in memory.
- The tool works on Linux and Windows (with GCC).
- GitHub Workflow included
