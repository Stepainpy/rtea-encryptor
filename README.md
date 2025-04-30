# RTEA encryptor

> [!Warning]
> This program is not intended to provide true protection against real-world attacks. Instead, it serves as a demonstration of the algorithm and encryption method.

Implementation of file encryptor with algorithm RTEA-256 and mode PCBC.

## Usage

``` console
$ rt256 <-e|-d> <key> <filename>
```
- `-e`/`-d` - switch en/decryption mode.
- `<key>` - secret 256-bit key in Base64.
- `<filename>` - path to input file (any or .rtea).

### Output file names

If is encryption, then add `.rtea` extention (`<filename>` -> `<filename>.rtea`).  
If is decryption, then remove last extention (`<filename>.*` -> `<filename>`), but not have extention, raise error.