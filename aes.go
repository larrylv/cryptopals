package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strconv"
)

// EncryptionMode - shut up golint
type EncryptionMode int

const (
	// EcbMode - shut up golint
	EcbMode EncryptionMode = iota
	// CbcMode - shut up golint
	CbcMode
)

// AesCipher - ECB or CBC mode
type AesCipher interface {
	Encrypt(plaintext []byte) []byte
	Decrypt(ciphertext []byte) []byte
}

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

// NewAesCipher returns an AES-128 cipher
func NewAesCipher(key []byte, mode EncryptionMode) (AesCipher, error) {
	switch len(key) {
	case 16, 24, 32:
		cipherBlock, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		if mode == EcbMode {
			return &AesEcbCipher{cipherBlock}, nil
		}
		return nil, fmt.Errorf("unknown encryption mode: %v", mode)
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
	if len(decrypted) > 1 {
		paddedByte := decrypted[len(decrypted)-1]
		endIdx := len(decrypted) - int(paddedByte)
		decrypted = decrypted[:endIdx]
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
