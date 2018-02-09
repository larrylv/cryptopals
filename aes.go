package main

import (
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

// DetectAesInEcbMode returns if the cipher is encrypted with AES in ECB mode
func DetectAesInEcbMode(cipher []byte) bool {
	m := make(map[string]bool)
	blockSize := aes.BlockSize

	for i := 0; i+1 <= len(cipher)/blockSize; i++ {
		block := cipher[i*blockSize : (i+1)*blockSize]
		if m[string(block)] {
			return true
		}
		m[string(block)] = true
	}

	return false
}
