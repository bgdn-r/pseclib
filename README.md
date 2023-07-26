# Package pseclib

**pseclib** is a Go (Golang) package that provides various cryptographic 
functions for password generation, password hashing, and AES encryption. 
It includes functions to generate strong random passwords, hash passwords 
using Argon2, and encrypt/decrypt data using AES encryption.

## Installation

To use this package, you need to have Go installed on your system. 
You can install the package using `go get`:

```bash
go get github.com/bgdn-r/pseclib
```

## Usage

```go
import (
	"github.com/bgdn-r/pseclib"
)
```

### Password Generation

Generate a random password with specific options:

```go
opts := &pseclib.GeneratePasswdOpts{
	Lowercase: true,
	Uppercase: true,
	Numbers:   true,
	Symbols:   true,
	Length:    16,
}

password, err := pseclib.GeneratePasswd(opts)
if err != nil {
	// Handle error
}
```

### Argon2 Password Hashing

Hash a password using Argon2 and get the encoded hash:

```go
plaintextPassword := "mySecretPassword"
encodedHash, err := pseclib.HashArgon2(plaintextPassword)
if err != nil {
	// Handle error
}
```

Verify a password against an encoded Argon2 hash:

```go
encodedHash := "$argon2id$v=19$m=65536,t=3,p=2$0Wj/8O2kq2UMi2NR0XUJUQ$ycKQz6Z26D0XJ+agFaaPc2E7CqHvX18SZCIM2Mwu6Ac"
match, err := pseclib.VerifyArgon2(plaintextPassword, encodedHash)
if err != nil {
	// Handle error
}
if match {
	// Password is correct
} else {
	// Password is incorrect
}
```

### AES Encryption

Encrypt and decrypt data using AES encryption:

```go
plaintext := "Sensitive information"
aesKey, err := pseclib.GenerateAESKey()
if err != nil {
	// Handle error
}

aesIV, err := pseclib.GenerateAESIV()
if err != nil {
	// Handle error
}

encrypted, err := pseclib.EncryptAES(plaintext, aesKey, aesIV)
if err != nil {
	// Handle error
}

decrypted, err := pseclib.DecryptAES(encrypted, aesKey, aesIV)
if err != nil {
	// Handle error
}
```

## Constants

- `minpasswdlength`: The minimum allowed password length.
- `maxpasswdlength`: The maximum allowed password length.
- `validhashlength`: The expected number of segments in the encoded Argon2 hash.

## Types

### GeneratePasswdOpts

```go
type GeneratePasswdOpts struct {
	Lowercase bool // Include lowercase characters in the generated password.
	Uppercase bool // Include uppercase characters in the generated password.
	Numbers   bool // Include numeric characters in the generated password.
	Symbols   bool // Include symbol characters in the generated password.
	Length    int  // Length of the generated password.
}
```

### Argon2Params

```go
type Argon2Params struct {
	memory      uint32 // Memory parameter for Argon2.
	iterations  uint32 // Iterations parameter for Argon2.
	parallelism uint8  // Parallelism parameter for Argon2.
	saltlength  uint32 // Length of the salt used in Argon2.
	keylength   uint32 // Length of the generated hash key.
}
```

## Functions

- `GeneratePasswd`: Generate a random password based on the provided options.
- `HashArgon2`: Compute the Argon2 hash of the given plaintext password.
- `VerifyArgon2`: Verify the given plaintext password against the provided encoded hash.
- `EncryptAES`: Encrypt the provided plaintext using AES encryption.
- `DecryptAES`: Decrypt the provided base64-encoded ciphertext using AES decryption.
- `GenerateAESKey`: Generate a random AES encryption key.
- `GenerateAESIV`: Generate a random AES initialization vector (IV).

## Errors

- `errInvalidPasswdOpts`: Indicates invalid password options.
- `errInvalidPasswdLength`: Indicates an invalid password length.
- `errFailedToGeneratePasswd`: Indicates a failure to generate a password.
- `errFailedToDecodeBase64`: Indicates a failure to decode a base64 string.
- `errFailedToCreateAESCipher`: Indicates a failure to create an AES cipher.
- `errInvalidCiphertextSize`: Indicates an invalid ciphertext size.
- `errFailedToGenerateAESKey`: Indicates a failure to generate an AES key.
- `errFailedToGenerateAESIV`: Indicates a failure to generate an AES IV.
- `errInvalidHashFormat`: Indicates that the encoded hash is not in the correct format.
- `errIncompatibleArgon2Version`: Indicates an incompatible version of Argon2.

## Notes

- The `argon2params` variable defines the default parameters for Argon2 hashing. You can customize these parameters according to your needs.

## License

This package is distributed under the MIT License. See the `LICENSE` file for more information.
