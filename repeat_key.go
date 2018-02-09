package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

// RepeatKeyXor encrypts the string using repeat-key XOR
func RepeatKeyXor(key []byte, str []byte) ([]byte, error) {
	var xor []byte
	keyLen := len(key)

	for i, b := range str {
		r, err := Xor([]byte{key[i%keyLen]}, []byte{byte(b)})
		if err != nil {
			return nil, errors.New("RepeatKeyXor errored")
		}
		xor = append(xor, r...)
	}

	return []byte(hex.EncodeToString(xor)), nil
}

// DecryptRepeatKeyXor decrypts the cipher which the original
// string is xor'ed by repeat-key
func DecryptRepeatKeyXor(cipher []byte) ([]byte, error) {
	decodedCipher, err := base64.StdEncoding.DecodeString(string(cipher))
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXor: %v", err)
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
			return nil, fmt.Errorf("DecryptRepeatKeyXor: %v", err)
		}
		key = append(key, singleKey)
	}

	decrypted, err := RepeatKeyXor(key, decodedCipher)
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXor: %v", err)
	}

	decoded, err := hex.DecodeString(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("DecryptRepeatKeyXor: %v", err)
	}

	return decoded, nil
}
