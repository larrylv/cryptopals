package util

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

// XorWithSingleByte takes a key, a string and returns the result of
// the string being XOR'd by the key
func XorWithSingleByte(key byte, a []byte) ([]byte, error) {
	b := bytes.Repeat([]byte{key}, len(a))

	return Xor(a, b)
}

// FindSingleXorByte finds the single byte which is used to XOR
// the original string
func FindSingleXorByte(ciphertext []byte) (byte, error) {
	maxScore := math.Inf(-1)
	var resKey byte

	for key := 0; key <= 255; key++ {
		s, err := XorWithSingleByte(byte(key), ciphertext)
		if err != nil {
			return byte(0), fmt.Errorf("FinderSingleKeyForXorCipher: %v", err)
		}

		tmpScore := ScoringEnglish(s)
		if tmpScore > maxScore {
			maxScore = tmpScore
			resKey = byte(key)
		}
	}

	return resKey, nil
}

// DetectStringXoredWithSingleKey detects one line in a file
// being XOR'ed by a single key
func DetectStringXoredWithSingleKey(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("DetectStringXoredWithSingleKey: got an error %v", err)
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
			return nil, fmt.Errorf("DetectStringXoredWithSingleKey: %v", err)
		}

		curKey, err := FindSingleXorByte(curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringXoredWithSingleKey: %v", err)
		}

		curDecrypted, err := XorWithSingleByte(curKey, curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringXoredWithSingleKey: %v", err)
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
