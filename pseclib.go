package pseclib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Password generation config
	lowercase = "abcdefghijklmnopqrstuvwxyz"
	uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers   = "0123456789"
	symbols   = "!@#$%^&*()-_=+,.?/:;{}[]~"

	// Min and max password length
	minpasswdlength int = 6
	maxpasswdlength int = 128

	// Argon2 configs
	memory      uint32 = 64 * 1024
	iterations  uint32 = 12
	parallelism uint8  = 2
	saltlength  uint32 = 16
	keylength   uint32 = 32

	// Valid hash length
	validhashlength int = 6

	// AES configs
	aeskeysize int = 32
	aesivsize  int = 16
)

var (
	// Password generation errors
	errInvalidPasswdOpts      = errors.New("invalid password options")
	errInvalidPasswdLength    = errors.New("invalid password length")
	errFailedToGeneratePasswd = errors.New("failed to generate password")

	// Base64 errors
	errFailedToDecodeBase64 = errors.New("failed to decode base64")

	// AES errors
	errFailedToCreateAESCipher = errors.New("failed to create AES cipher")
	errInvalidCiphertextSize   = errors.New("invalid ciphertext size")
	errFailedToGenerateAESKey  = errors.New("failed to generate AES key")
	errFailedToGenerateAESIV   = errors.New("failed to generate AES IV")

	// Argon2 errors
	errInvalidHashFormat         = errors.New("the encoded hash is not in correct format")
	errIncompatibleArgon2Version = errors.New("incompatible version of Argon2")
)

// GeneratePasswdOpts defines the options for password generation.
type GeneratePasswdOpts struct {
	Lowercase bool // Include lowercase characters in the generated password.
	Uppercase bool // Include uppercase characters in the generated password.
	Numbers   bool // Include numeric characters in the generated password.
	Symbols   bool // Include symbol characters in the generated password.
	Length    int  // Length of the generated password.
}

// Argon2Params defines the parameters for Argon2 hashing.
type Argon2Params struct {
	memory      uint32 // Memory parameter for Argon2.
	iterations  uint32 // Iterations parameter for Argon2.
	parallelism uint8  // Parallelism parameter for Argon2.
	saltlength  uint32 // Length of the salt used in Argon2.
	keylength   uint32 // Length of the generated hash key.
}

var argon2params = &Argon2Params{
	memory,
	iterations,
	parallelism,
	saltlength,
	keylength,
}

// GeneratePasswd generates a random password based on the provided options.
// It returns the generated password as a string.
func GeneratePasswd(opts *GeneratePasswdOpts) (string, error) {
	if opts.Length == 0 ||
		opts.Length < minpasswdlength ||
		opts.Length > maxpasswdlength {
		return "", fmt.Errorf("%w: %s: min value=%d max value=%d",
			errInvalidPasswdOpts,
			errInvalidPasswdLength,
			minpasswdlength,
			maxpasswdlength,
		)
	}

	var charsbuilder strings.Builder

	if opts.Lowercase {
		charsbuilder.WriteString(lowercase) // Include lowercase characters
	}

	if opts.Uppercase {
		charsbuilder.WriteString(uppercase) // Include uppercase characters
	}

	if opts.Numbers {
		charsbuilder.WriteString(numbers) // Include numeric characters
	}

	if opts.Symbols {
		charsbuilder.WriteString(symbols) // Include symbol characters
	}

	chars := charsbuilder.String()

	if chars == "" {
		return "", fmt.Errorf("%w: %s",
			errInvalidPasswdOpts,
			"no characters selected",
		)
	}

	passwd := make([]byte, opts.Length)

	for i := 0; i < opts.Length; i++ {
		randomindex, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("%w: %v",
				errFailedToGeneratePasswd,
				err,
			)
		}

		passwd[i] = chars[randomindex.Int64()]
	}

	return string(passwd), nil
}

// EncryptAES encrypts the provided plaintext using AES encryption with
// the given key and initialization vector (IV).
// It returns the encrypted ciphertext as a base64-encoded string.
func EncryptAES(plaintext, key, iv string) (string, error) {
	var plaintextblock []byte

	// Decode key from base64
	keybytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToDecodeBase64, err)
	}

	// Decode IV from base64
	ivbytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToDecodeBase64, err)
	}

	length := len(plaintext)

	if length%aesivsize != 0 {
		extendblock := aeskeysize - (length % aesivsize)
		// Extend plaintext block size to match AES block size
		plaintextblock = make([]byte, length+extendblock)
		copy(plaintextblock[length:], bytes.Repeat([]byte{uint8(extendblock)}, extendblock))
	} else {
		plaintextblock = make([]byte, length)
	}

	copy(plaintextblock, plaintext)

	// Create AES cipher with the provided key
	block, err := aes.NewCipher(keybytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v",
			errFailedToCreateAESCipher,
			err,
		)
	}

	ciphertext := make([]byte, len(plaintextblock))

	// Create CBC mode encrypter
	mode := cipher.NewCBCEncrypter(block, ivbytes)
	// Encrypt the plaintext block using the AES cipher in CBC mode
	mode.CryptBlocks(ciphertext, plaintextblock)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptAES decrypts the provided base64-encoded ciphertext using AES
// decryption with the given key and initialization vector (IV).
// It returns the decrypted plaintext as a string.
func DecryptAES(encrypted, key, iv string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToDecodeBase64, err)
	}

	keybytes, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToDecodeBase64, err)
	}

	ivbytes, err := base64.StdEncoding.DecodeString(iv)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToDecodeBase64, err)
	}

	block, err := aes.NewCipher(keybytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToCreateAESCipher, err)
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return "", errInvalidCiphertextSize
	}

	mode := cipher.NewCBCDecrypter(block, ivbytes)
	mode.CryptBlocks(ciphertext, ciphertext)

	ciphertext = removePKCS5Padding(ciphertext)

	return string(ciphertext), nil
}

// GenerateAESKey generates a random AES encryption key and returns
// it as a base64-encoded string.
func GenerateAESKey() (string, error) {
	keybytes := make([]byte, aeskeysize)

	_, err := io.ReadFull(rand.Reader, keybytes)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToGenerateAESKey, err)
	}

	return base64.StdEncoding.EncodeToString(keybytes), nil
}

// GenerateAESIV generates a random AES initialization vector (IV)
// and returns it as a base64-encoded string.
func GenerateAESIV() (string, error) {
	iv := make([]byte, aesivsize)

	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		return "", fmt.Errorf("%w: %v", errFailedToGenerateAESIV, err)
	}

	return base64.StdEncoding.EncodeToString(iv), nil
}

// removePKCS5Padding removes the PKCS5 padding from the given ciphertext
// and returns the unpadded ciphertext.
func removePKCS5Padding(ciphertext []byte) []byte {
	length := len(ciphertext)
	unpadding := int(ciphertext[length-1])

	return ciphertext[:length-unpadding]
}

// HashArgon2 computes the Argon2 hash of the given plaintext password.
// It returns the encoded hash as a string.
func HashArgon2(plaintext string) (encodedhash string, err error) {
	salt, err := generateRandomBytes(argon2params.saltlength)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(plaintext),
		salt,
		argon2params.iterations,
		argon2params.memory,
		argon2params.parallelism,
		argon2params.keylength,
	)

	base64salt := base64.RawStdEncoding.EncodeToString(salt)
	base64hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedhash = fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2params.memory,
		argon2params.iterations,
		argon2params.parallelism,
		base64salt,
		base64hash,
	)

	return encodedhash, nil
}

// VerifyArgon2 verifies the given plaintext password against the provided
// encoded hash. It returns true if the password matches the hash,
// and false otherwise.
func VerifyArgon2(plaintext, encodedhash string) (match bool, err error) {
	p, salt, hash, err := decodeHash(encodedhash)
	if err != nil {
		return false, err
	}

	otherhash := argon2.IDKey([]byte(plaintext),
		salt,
		p.iterations,
		p.memory,
		p.parallelism,
		p.keylength,
	)

	return subtle.ConstantTimeCompare(hash, otherhash) == 1, nil
}

// generateRandomBytes generates n random bytes using the cryptographic
// random number generator.
func generateRandomBytes(n uint32) ([]byte, error) {
	bs := make([]byte, n)

	_, err := rand.Read(bs)
	if err != nil {
		return nil, err
	}

	return bs, nil
}

// decodeHash decodes the encoded hash string and returns the Argon2
// parameters, salt, and hash bytes.
func decodeHash(encodedhash string) (p *Argon2Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedhash, "$")
	if len(vals) != validhashlength {
		return nil, nil, nil, errInvalidHashFormat
	}

	var version int

	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}

	if version != argon2.Version {
		return nil, nil, nil, errIncompatibleArgon2Version
	}

	// Initialize Argon2Params struct
	p = &Argon2Params{}

	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	// Decode salt from base64
	salt, err = base64.RawStdEncoding.Strict().DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}

	// Set salt length in Argon2Params struct
	p.saltlength = uint32(len(salt))

	// Decode hash from base64
	hash, err = base64.RawStdEncoding.Strict().DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}

	// Set hash key length in Argon2Params struct
	p.keylength = uint32(len(hash))

	return p, salt, hash, nil
}
