package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"os"
)

// FindSingleXorByte finds the single byte which is used to XOR
// the original string
func FindSingleXorByte(cipher []byte) (byte, error) {
	maxScore := math.Inf(-1)
	var resKey byte

	for key := 0; key <= 255; key++ {
		s, err := SingleByteXor(byte(key), cipher)
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

// DetectStringEncryptedWithSingleXorKey detects one line in a file
// being XOR'ed by a single key
func DetectStringEncryptedWithSingleXorKey(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("DetectStringEncryptedWithSingleXorKey: got an error %v", err)
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
			return nil, fmt.Errorf("DetectStringEncryptedWithSingleXorKey: %v", err)
		}

		curKey, err := FindSingleXorByte(curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringEncryptedWithSingleXorKey: %v", err)
		}

		curDecrypted, err := SingleByteXor(curKey, curDecoded)
		if err != nil {
			return nil, fmt.Errorf("DetectStringEncryptedWithSingleXorKey: %v", err)
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
