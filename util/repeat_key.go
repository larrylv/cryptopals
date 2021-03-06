package util

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
)

// XorWithRepeatKey encrypts the string using repeat-key XOR
func XorWithRepeatKey(key []byte, str []byte) ([]byte, error) {
	var xor []byte
	keyLen := len(key)

	for i, b := range str {
		r, err := Xor([]byte{key[i%keyLen]}, []byte{byte(b)})
		if err != nil {
			return nil, errors.New("XorWithRepeatKey errored")
		}
		xor = append(xor, r...)
	}

	return []byte(hex.EncodeToString(xor)), nil
}

// DecryptStringXoredWithRepeatKey decrypts the ciphertext that is xor encrypted with repeat-key
func DecryptStringXoredWithRepeatKey(ciphertext []byte) ([]byte, error) {
	decodedCipher, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, fmt.Errorf("DecryptStringXoredWithRepeatKey: %v", err)
	}

	keySize := findRepeatKeySize(decodedCipher)
	var key []byte

	for i := 0; i < keySize; i++ {
		var curBlock []byte
		for j := i; j < len(decodedCipher); j += keySize {
			curBlock = append(curBlock, decodedCipher[j])
		}

		singleByte, err := FindSingleXorByte(curBlock)
		if err != nil {
			return nil, fmt.Errorf("DecryptStringXoredWithRepeatKey: %v", err)
		}
		key = append(key, singleByte)
	}

	decrypted, err := XorWithRepeatKey(key, decodedCipher)
	if err != nil {
		return nil, fmt.Errorf("DecryptStringXoredWithRepeatKey: %v", err)
	}

	decoded, err := hex.DecodeString(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("DecryptStringXoredWithRepeatKey: %v", err)
	}

	return decoded, nil
}

// findRepeatKeySize returns the most possible repeat-key size for the ciphertext
func findRepeatKeySize(ciphertext []byte) int {
	keySize := 0
	minDistance := math.Inf(1)

	for i := 2; i <= 64; i++ {
		// exceeds the ciphertext length
		if 2*i > len(ciphertext) {
			break
		}

		distance := 0.0
		cnt := 0

		for j := 0; j < 10 && (j+2)*i <= len(ciphertext); j++ {
			distance += float64(HammingDistance(ciphertext[j*i:(j+1)*i], ciphertext[(j+1)*i:(j+2)*i]))
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
