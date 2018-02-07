package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
)

// HexToBase64 converts a hex string to base64 encoded string
func HexToBase64(s string) (string, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}

// Xor takes two strings and returns their XOR combination
func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("byte arrays have different length")
	}

	n := len(a)
	dst := make([]byte, n)

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return dst, nil
}

// SingleByteXor takes a key, a string and returns the result of
// the string being XOR'd by the key
func SingleByteXor(key byte, a []byte) ([]byte, error) {
	b := bytes.Repeat([]byte{key}, len(a))

	return Xor(a, b)
}

// FindSingleKeyForXorCipher finds the single key which is used to XOR
// the original message
func FindSingleKeyForXorCipher(cipher []byte) ([]byte, error) {
	maxScore := math.Inf(-1)
	var resKey []byte

	for key := 0; key <= 255; key++ {
		s, err := SingleByteXor(byte(key), cipher)
		if err != nil {
			return nil, fmt.Errorf("FinderSingleKeyForXorCipher: %v", err)
		}

		tmpScore := ScoringEnglish(s)
		if tmpScore > maxScore {
			maxScore = tmpScore
			resKey = []byte{byte(key)}
		}
	}

	return resKey, nil
}

// DetectStringBeingXoredWithSingleKey detects one line in a file
// being XOR'ed by a single key
func DetectStringBeingXoredWithSingleKey(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("DetectStringBeingXoredWithSingleKey: got an error %v", err)
	}
	defer file.Close()

	maxScore := 0.0
	var result []byte

	reader := bufio.NewReader(file)
	for {
		curLine, _, err := reader.ReadLine()
		if err != nil {
			break
		}

		curDecoded, err := hex.DecodeString(string(curLine))
		if err != nil {
			return nil, fmt.Errorf("DetectStringBeingXoredWithSingleKey: %v", err)
		}

		curKey, err := FindSingleKeyForXorCipher(curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringBeingXoredWithSingleKey: %v", err)
		}

		curDecrypted, err := SingleByteXor(curKey[0], curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringBeingXoredWithSingleKey: %v", err)
		}

		curScore := ScoringEnglish(curDecrypted)
		if curScore > maxScore {
			maxScore = curScore
			result = make([]byte, len(curDecrypted))
			copy(result, curDecrypted)
		}
	}

	return result, nil
}