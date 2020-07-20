package aes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"testing"
)

func TestDetectBlockSize(t *testing.T) {
	encodedSalt := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	salt, _ := base64.StdEncoding.DecodeString(encodedSalt)
	key := generateRandomBytes(aes.BlockSize)

	cipher, err := NewAesEcbOracleCipher(key, nil, salt)
	if err != nil {
		t.Errorf("TestDetectBlockSize: got an error %v", err)
		return
	}

	keySize := cipher.detectBlockSize()
	if keySize != aes.BlockSize {
		t.Errorf("TestDetectBlockSize: expected %d, got %d", aes.BlockSize, keySize)
	}
}

func TestDetectSaltSize(t *testing.T) {
	for expectedSaltSize := 0; expectedSaltSize < 100; expectedSaltSize += 4 {
		key := generateRandomBytes(aes.BlockSize)
		salt := generateRandomBytes(expectedSaltSize)

		cipher, err := NewAesEcbOracleCipher(key, nil, salt)
		if err != nil {
			t.Errorf("TestDetectBlockSize: got an error %v", err)
			return
		}

		saltSize := cipher.detectSaltSize()
		if expectedSaltSize != saltSize {
			t.Errorf("TestDetectSaltSize: expected %d, got %d", expectedSaltSize, saltSize)
		}
	}
}

func TestDecryptSalt(t *testing.T) {
	key := generateRandomBytes(aes.BlockSize)
	encodedSalt := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	expectedSalt, _ := base64.StdEncoding.DecodeString(encodedSalt)
	cipher, err := NewAesEcbOracleCipher(key, nil, expectedSalt)
	if err != nil {
		t.Errorf("TestDetectBlockSize: got an error %v", err)
		return
	}

	salt := cipher.DecryptSalt()
	if !bytes.Equal(expectedSalt, salt) {
		t.Errorf("TestDecryptSalt: expected %s, got %v", expectedSalt, salt)
		return
	}
}
