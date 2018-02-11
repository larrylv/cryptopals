package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/larrylv/cryptopals/util"
)

// EcbCipher is just an AES ECB mode cipher...
type EcbCipher struct {
	cipherBlock cipher.Block
}

// NewAesEcbCipher returns an AES ECB cipher
func NewAesEcbCipher(key []byte) (Cipher, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &EcbCipher{cipherBlock}, nil

}

// BlockEncrypt of AesEcbCipher encrypts exactly one block
func (cipher *EcbCipher) BlockEncrypt(plaintext []byte) []byte {
	if len(plaintext) != aes.BlockSize {
		return nil
	}

	encrypted := make([]byte, len(plaintext))
	cipher.cipherBlock.Encrypt(encrypted, plaintext)

	return encrypted
}

// Encrypt of AesEcbCipher implements Encrypt function of aesCipher interface
func (cipher *EcbCipher) Encrypt(plaintext []byte) []byte {
	paddedPlainText, err := util.PKCS7Padding([]byte(plaintext), aes.BlockSize)
	if err != nil {
		fmt.Errorf("AesEcbCipher.Encrypt error: %v", err)
		return nil
	}

	encrypted := make([]byte, len(paddedPlainText))
	for bs, be := 0, aes.BlockSize; be <= len(paddedPlainText); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		copy(encrypted[bs:be], cipher.BlockEncrypt(paddedPlainText[bs:be]))
	}

	return encrypted
}

// BlockDecrypt of AesEcbCipher decrypts exactly one block
func (cipher *EcbCipher) BlockDecrypt(ciphertext []byte) []byte {
	if len(ciphertext) != aes.BlockSize {
		return nil
	}

	decrypted := make([]byte, len(ciphertext))
	cipher.cipherBlock.Decrypt(decrypted, ciphertext)

	return decrypted
}

// Decrypt of AesEcbCipher implements Decrypt function of aesCipher interface
func (cipher *EcbCipher) Decrypt(ciphertext []byte) []byte {
	decrypted := make([]byte, len(ciphertext))
	for bs, be := 0, aes.BlockSize; be <= len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		copy(decrypted[bs:be], cipher.BlockDecrypt(ciphertext[bs:be]))
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
	blockSize := aes.BlockSize

	for i := 0; i+1 <= len(ciphertext)/blockSize; i++ {
		block := ciphertext[i*blockSize : (i+1)*blockSize]
		if m[string(block)] {
			return true
		}
		m[string(block)] = true
	}

	return false
}
