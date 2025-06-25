# verifiy_file.exe

## Overview
An attempt to emulate producing idiomatic Rust to make checking downloaded file hashes a bit less annoying. This tool supports multiple hash algorithms, including MD5, SHA1, SHA256, and SHA512.

## Features
- Supports hash algorithms: MD5, SHA1, SHA256, SHA512.
- Designed to simplify file hash verification.

## Caveat Emptor
Trust, but verify! Always double-check the results.

## Usage
### Example: Using PowerShell to Output SHA512 Without Truncation
```powershell
get-filehash -algorithm sha512 example.exe | format-list > example.sha512
```

## License
This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
