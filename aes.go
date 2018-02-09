package main

import (
	"crypto/aes"
	"crypto/cipher"
	"strconv"
)

// type aesCipher interface {
// 	Encrypt(plaintext []byte) []byte
// 	Decrypt(ciphertext []byte) []byte
// }

// AesEcbCipher is just an AES ECB mode cipher...
type AesEcbCipher struct {
	cipherBlock cipher.Block
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
	switch len(key) {
	case 16, 24, 32:
		cipherBlock, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return &AesEcbCipher{cipherBlock}, nil
	default:
		break
	}

	return nil, KeySizeError(len(key))
}

// Encrypt of AesEcbCipher implements Encrypt function of aesCipher interface
func (cipher *AesEcbCipher) Encrypt(plaintext []byte) []byte {
	encrypted := make([]byte, len(plaintext))
	for bs, be := 0, BlockSize; be <= len(plaintext); bs, be = bs+BlockSize, be+BlockSize {
		cipher.cipherBlock.Encrypt(encrypted[bs:be], plaintext[bs:be])
	}

	return encrypted
}

// Decrypt of AesEcbCipher implements Decrypt function of aesCipher interface
func (cipher *AesEcbCipher) Decrypt(ciphertext []byte) []byte {
	decrypted := make([]byte, len(ciphertext))
	for bs, be := 0, BlockSize; be <= len(ciphertext); bs, be = bs+BlockSize, be+BlockSize {
		cipher.cipherBlock.Decrypt(decrypted[bs:be], ciphertext[bs:be])
	}

	return decrypted
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
