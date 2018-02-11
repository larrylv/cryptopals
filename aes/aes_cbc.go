package aes

import (
	"crypto/aes"
	"fmt"

	"github.com/larrylv/cryptopals/util"
)

// CbcCipher is just an AES CBC mode cipher...
type CbcCipher struct {
	ecbCipher *EcbCipher
	iv        []byte
}

// NewAesCbcCipher returns an AES CBC cipher
func NewAesCbcCipher(key []byte, iv []byte) (Cipher, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	aesCipher, err := NewAesEcbCipher(key, nil)
	if err != nil {
		return nil, err
	}

	return &CbcCipher{
		ecbCipher: aesCipher.(*EcbCipher),
		iv:        iv,
	}, nil
}

// Encrypt of AesCbcCipher implements Encrypt function of aesCipher interface
func (cipher *CbcCipher) Encrypt(plaintext []byte) []byte {
	paddedPlainText, err := util.PKCS7Padding([]byte(plaintext), aes.BlockSize)
	if err != nil {
		fmt.Errorf("AesEcbCipher.Encrypt error: %v", err)
		return nil
	}

	curIV := make([]byte, len(cipher.iv))
	copy(curIV, cipher.iv)
	encrypted := make([]byte, len(paddedPlainText))

	for bs, be := 0, aes.BlockSize; be <= len(paddedPlainText); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		// ignore the error since curIV and the block will always have the same size
		combinedText, _ := util.Xor(paddedPlainText[bs:be], curIV)
		copy(encrypted[bs:be], cipher.ecbCipher.BlockEncrypt(combinedText))
		copy(curIV, encrypted[bs:be])
	}

	return encrypted
}

// Decrypt of AesCbcCipher implements Decrypt function of aesCipher interface
func (cipher *CbcCipher) Decrypt(ciphertext []byte) []byte {
	curIV := make([]byte, len(cipher.iv))
	copy(curIV, cipher.iv)
	decrypted := make([]byte, len(ciphertext))

	for bs, be := 0, aes.BlockSize; be <= len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		// ignore the error since curIV and the block will always have the same size
		combinedText, _ := util.Xor(cipher.ecbCipher.BlockDecrypt(ciphertext[bs:be]), curIV)
		copy(decrypted[bs:be], combinedText)
		copy(curIV, ciphertext[bs:be])
	}

	if len(decrypted) > 1 {
		paddedByte := decrypted[len(decrypted)-1]
		endIdx := len(decrypted) - int(paddedByte)
		decrypted = decrypted[:endIdx]
	}

	return decrypted
}
