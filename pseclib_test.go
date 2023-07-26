package pseclib_test

import (
	"encoding/base64"
	"testing"

	"github.com/bgdn-r/pseclib"
)

var (
	generatedpasswd string
	generatedaeskey string
	generatedaesiv  string
	encryptedpasswd string
	encodedhash     string
)

// TestGeneratePassword tests the GeneratePasswd function.
// It generates a random password based on the provided options.
func TestGeneratePassword(t *testing.T) {
	// Valid options for password generation
	validopts := &pseclib.GeneratePasswdOpts{
		Lowercase: true,
		Uppercase: true,
		Numbers:   true,
		Symbols:   true,
		Length:    12,
	}

	passwd, err := pseclib.GeneratePasswd(validopts)
	if err != nil {
		t.Errorf("failed to generate password: %s", err)
	}

	if len(passwd) != validopts.Length {
		t.Errorf("generated password does not have correct length")
	}

	generatedpasswd = passwd

	// TestGeneratePassword with invalid options
	invalidopts := &pseclib.GeneratePasswdOpts{
		Lowercase: false,
		Uppercase: false,
		Numbers:   false,
		Symbols:   false,
		Length:    0,
	}

	_, err = pseclib.GeneratePasswd(invalidopts)
	if err == nil {
		t.Errorf("password was generated with invalid options")
	}

	// TestGeneratePassword with invalid length
	invalidopts.Length = 5
	invalidopts.Lowercase = true

	_, err = pseclib.GeneratePasswd(invalidopts)
	if err == nil {
		t.Errorf("password was generated with invalid length")
	}

	// TestGeneratePassword with invalid length
	invalidopts.Length = 129

	_, err = pseclib.GeneratePasswd(invalidopts)
	if err == nil {
		t.Errorf("password was generated with invalid length")
	}
}

// TestGenerateAESKey tests the GenerateAESKey function.
// It generates a random AES encryption key and ensures it is base64-encoded.
func TestGenerateAESKey(t *testing.T) {
	key, err := pseclib.GenerateAESKey()
	if err != nil {
		t.Errorf("failed to generate AES key: %s", err)
	}

	if _, err := base64.StdEncoding.DecodeString(key); err != nil {
		t.Errorf("base64 failed to decode key string: %s", err)
	}

	generatedaeskey = key
}

// TestGenerateAESIV tests the GenerateAESIV function.
// It generates a random AES initialization vector (IV) and ensures it is base64-encoded.
func TestGenerateAESIV(t *testing.T) {
	iv, err := pseclib.GenerateAESIV()
	if err != nil {
		t.Errorf("failed to generate AES IV: %s", err)
	}

	if _, err := base64.StdEncoding.DecodeString(iv); err != nil {
		t.Errorf("base64 failed to decode IV string: %s", err)
	}

	generatedaesiv = iv
}

// TestEncryptAES tests the EncryptAES function.
// It encrypts the generated password using AES encryption with the generated key and IV.
func TestEncryptAES(t *testing.T) {
	encrypted, err := pseclib.EncryptAES(generatedpasswd, generatedaeskey, generatedaesiv)
	if err != nil {
		t.Errorf("failed to encrypt password: %s", err)
	}

	encryptedpasswd = encrypted
}

// TestDecryptAES tests the DecryptAES function.
// It decrypts the encrypted password using AES decryption with the generated key and IV,
// and ensures that the decrypted password matches the original password.
func TestDecryptAES(t *testing.T) {
	decrypted, err := pseclib.DecryptAES(encryptedpasswd, generatedaeskey, generatedaesiv)
	if err != nil {
		t.Errorf("failed to decrypt password: %s", err)
	}

	if decrypted != generatedpasswd {
		t.Errorf("decrypted password does not match original password")
	}
}

// TestHashArgon2 tests the HashArgon2 function.
// It computes the Argon2 hash of the generated password and ensures that the encoded hash is generated successfully.
func TestHashArgon2(t *testing.T) {
	hashed, err := pseclib.HashArgon2(generatedpasswd)
	if err != nil {
		t.Errorf("failed to hash password: %s", err)
	}

	encodedhash = hashed
}

// TestVerifyArgon2 tests the VerifyArgon2 function.
// It verifies the generated password against the encoded hash and ensures that the password matches the hash.
func TestVerifyArgon2(t *testing.T) {
	match, err := pseclib.VerifyArgon2(generatedpasswd, encodedhash)
	if err != nil {
		t.Errorf("failed to verify password: %s", err)
	}

	if !match {
		t.Errorf("encoded hash does not match but it should")
	}

	// TestVerifyArgon2 with mismatched password
	match, err = pseclib.VerifyArgon2("nomatch", encodedhash)
	if err != nil {
		t.Errorf("failed to verify password: %s", err)
	}

	if match {
		t.Errorf("encoded hash does match but it shouldn't")
	}
}
