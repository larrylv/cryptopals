package main

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"fmt"
)

// DecryptAesEcbCipher decrypts the AES (EBC mode) encrypted cipher with the given key
func DecryptAesEcbCipher(key, cipher []byte) ([]byte, error) {
	decodedCipher, err := base64.StdEncoding.DecodeString(string(cipher))
	if err != nil {
		return nil, fmt.Errorf("DecryptAesEcbCipher: %v", err)
	}

	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("DecryptAesEcbCipher: %v", err)
	}

	size := aes.BlockSize
	decrypted := make([]byte, len(decodedCipher))
	for bs, be := 0, size; bs < len(decodedCipher); bs, be = bs+size, be+size {
		cipherBlock.Decrypt(decrypted[bs:be], decodedCipher[bs:be])
	}

	return decrypted, nil
}

// Pkcs7Padding implements PCKS#7 padding
func Pkcs7Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize > 255 || blockSize <= 0 {
		return nil, fmt.Errorf("Pkcs7Padding: invalid blockSize %d", blockSize)
	}

	paddedCnt := blockSize - (len(plaintext) % blockSize)
	paddedByte := byte(paddedCnt)

	cipher := append(plaintext, bytes.Repeat([]byte{paddedByte}, paddedCnt)...)

	return cipher, nil
}
