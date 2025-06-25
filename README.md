# verifiy_file.exe

## Caveat emptor! Trust, but verify! Etc.

### An attempt to emulate producing idiomtic rust to make checking downloaded file hashes a bit less annoying 
- Should work for md5, sha1, sha256, sha512

#### Notes
- When working with powershell's "get-filehash -algorithm sha512 *filepath*", remember to pipe the output through format-list, because get-filehash (is weird, and) truncates it's output by default.

```powershell
# Using get-filehash to output SHA512 without truncation
get-filehash -algorithm sha512 example.exe | format-list > example.sha512
```
