package aes

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestDetectionOracleForEcbMode(t *testing.T) {
	plaintext := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAPlay that funky musicAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	key := generateRandomBytes(aes.BlockSize)

	encrypted, err := encryptWithMode(key, plaintext, 0)
	if err != nil {
		t.Errorf("TestDetectionOracle: got an error %v", err)
		return
	}

	secondBlock := encrypted[16:32]
	if !bytes.Contains(encrypted[32:], secondBlock) {
		t.Errorf("TestDetectionOracleForEcbMode: CBC mode should have different encrypted texts for same plaintexts")
	}
}

func TestDetectionOracleForCbcMode(t *testing.T) {
	// the second block will always be 16 A, the third block from last is also 16 A
	plaintext := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAPlay that funky musicAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	key := generateRandomBytes(aes.BlockSize)

	encrypted, err := encryptWithMode(key, plaintext, 1)
	if err != nil {
		t.Errorf("TestDetectionOracle: got an error %v", err)
		return
	}

	secondBlock := encrypted[16:32]
	if bytes.Contains(encrypted[32:], secondBlock) {
		t.Errorf("TestDetectionOracleForEcbMode: CBC mode should have different encrypted texts for same plaintexts")
	}
}
