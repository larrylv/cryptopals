package main

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
)

// DecryptRepeatKeyXorCipher decrypts the cipher which the original
// string is xor'ed by repeat-key
func DecryptRepeatKeyXorCipher(cipher []byte) ([]byte, error) {
	decodedCipher, err := base64.StdEncoding.DecodeString(string(cipher))
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXorCipher: %v", err)
	}

	keySize := FindRepeatKeySize(decodedCipher)
	var key []byte

	for i := 0; i < keySize; i++ {
		var curBlock []byte
		for j := i; j < len(decodedCipher); j += keySize {
			curBlock = append(curBlock, decodedCipher[j])
		}

		singleKey, err := FindSingleKeyForXorCipher(curBlock)
		if err != nil {
			return nil, fmt.Errorf("DecryptRepeatKeyXorCipher: %v", err)
		}
		key = append(key, singleKey)
	}

	decrypted, err := RepeatKeyXor(key, decodedCipher)
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXorCipher: %v", err)
	}

	decoded, err := hex.DecodeString(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXorCipher: %v", err)
	}

	return decoded, nil
}

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

// FindRepeatKeySize returns the most possible repeat-key size for the cipher
func FindRepeatKeySize(cipher []byte) int {
	keySize := 0
	minDistance := math.Inf(1)

	for i := 2; i <= 64; i++ {
		// exceeds the cipher length
		if 2*i > len(cipher) {
			break
		}

		distance := 0.0
		cnt := 0

		for j := 0; j < 10 && (j+2)*i <= len(cipher); j++ {
			distance += float64(HammingDistance(cipher[j*i:(j+1)*i], cipher[(j+1)*i:(j+2)*i]))
			cnt++
		}

		distance /= float64(cnt * i)

		if distance < minDistance {
			keySize = i
			minDistance = distance
		}
	}

	return keySize
}
