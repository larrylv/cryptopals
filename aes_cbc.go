package main

import (
	"crypto/aes"
	"fmt"
)

// AesCbcCipher is just an AES CBC mode cipher...
type AesCbcCipher struct {
	ecbCipher *AesEcbCipher
	iv        []byte
}

// NewAesCbcCipher returns an AES CBC cipher
func NewAesCbcCipher(key []byte, iv []byte) (*AesCbcCipher, error) {
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("IV length must equal block size")
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AesCbcCipher{
		ecbCipher: &AesEcbCipher{cipherBlock},
		iv:        iv,
	}, nil
}

// Encrypt of AesCbcCipher implements Encrypt function of aesCipher interface
func (cipher *AesCbcCipher) Encrypt(plaintext []byte) []byte {
	paddedPlainText, err := PKCS7Padding([]byte(plaintext), aes.BlockSize)
	if err != nil {
		fmt.Errorf("AesEcbCipher.Encrypt error: %v", err)
		return nil
	}

	curIV := make([]byte, len(cipher.iv))
	copy(curIV, cipher.iv)
	encrypted := make([]byte, len(paddedPlainText))

	for bs, be := 0, aes.BlockSize; be <= len(paddedPlainText); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		// ignore the error since curIV and the block will always have the same size
		combinedText, _ := Xor(paddedPlainText[bs:be], curIV)
		copy(encrypted[bs:be], cipher.ecbCipher.BlockEncrypt(combinedText))
		copy(curIV, encrypted[bs:be])
	}

	return encrypted
}

// Decrypt of AesCbcCipher implements Decrypt function of aesCipher interface
func (cipher *AesCbcCipher) Decrypt(ciphertext []byte) []byte {
	curIV := make([]byte, len(cipher.iv))
	copy(curIV, cipher.iv)
	decrypted := make([]byte, len(ciphertext))

	for bs, be := 0, aes.BlockSize; be <= len(ciphertext); bs, be = bs+aes.BlockSize, be+aes.BlockSize {
		// ignore the error since curIV and the block will always have the same size
		combinedText, _ := Xor(cipher.ecbCipher.BlockDecrypt(ciphertext[bs:be]), curIV)
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
