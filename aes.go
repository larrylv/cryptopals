package main

import (
	"crypto/aes"
	"fmt"
	"strconv"
)

// type aesCipher interface {
// 	Encrypt(plaintext []byte) ([]byte, error)
// 	Decrypt(ciphertext []byte) ([]byte, error)
// }

// AesEcbCipher is just an AES ECB mode cipher...
type AesEcbCipher struct {
	key []byte
}

// KeySizeError is used when the key size is not supported
type KeySizeError int

func (k KeySizeError) Error() string {
	return "aes: invalid key size " + strconv.Itoa(int(k))
}

// BlockSize is the AES block size in bytes.
const BlockSize = 16

// NewAesEcbCipher returns an AES-128 ECB mode cipher
func NewAesEcbCipher(key []byte) (*AesEcbCipher, error) {
	if len(key) == 16 {
		return &AesEcbCipher{key: key}, nil
	}

	return nil, KeySizeError(len(key))
}

// Decrypt of AesEcbCipher implements Decrypt function of aesCipher interface
func (cipher *AesEcbCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	cipherBlock, err := aes.NewCipher(cipher.key)
	if err != nil {
		return nil, fmt.Errorf("AesEcbCipher.Decrypt: %v", err)
	}

	decrypted := make([]byte, len(ciphertext))
	for bs, be := 0, BlockSize; bs < len(ciphertext); bs, be = bs+BlockSize, be+BlockSize {
		cipherBlock.Decrypt(decrypted[bs:be], ciphertext[bs:be])
	}

	return decrypted, nil
}

// IsEncryptedWithAesEcbMode returns if the ciphertext is encrypted with AES in ECB mode
func IsEncryptedWithAesEcbMode(ciphertext []byte) bool {
	m := make(map[string]bool)
	blockSize := BlockSize

	for i := 0; i+1 <= len(ciphertext)/blockSize; i++ {
		block := ciphertext[i*blockSize : (i+1)*blockSize]
		if m[string(block)] {
			return true
		}
		m[string(block)] = true
	}

	return false
}
