package aes

import (
	"bytes"
	"testing"
)

func TestDetectionOracleForEcbMode(t *testing.T) {
	// the second block will always be 16 A, the third block from last is also 16 A
	plaintext := []byte("\x4f\x6d\x6b\x0b\x38\x76\x27\x5bAAAAAAAAAAAAAAAAAAAAAAAAAAAPlay that funky musicAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xcc\x5c\x27\xee\x1b\x6f")
	key := []byte("\xe7\x3a\x0e\xdb\xb2\x93\x18\x59\x7e\xe1\x6a\x8b\x4f\xda\xfd\xdd")

	encrypted, err := encryptWithMode(key, plaintext, 0)
	if err != nil {
		t.Errorf("TestDetectionOracle: got an error %v", err)
		return
	}
	secondBlock := encrypted[16:32]
	thridBlockFromLast := encrypted[len(encrypted)-48 : len(encrypted)-32]

	if bytes.Compare(secondBlock, thridBlockFromLast) != 0 {
		t.Errorf("TestDetectionOracleForEcbMode: ECB mode should have the same encrypted texts for same plaintexts")
	}
}

func TestDetectionOracleForCbcMode(t *testing.T) {
	// the second block will always be 16 A, the third block from last is also 16 A
	plaintext := []byte("\x4f\x6d\x6b\x0b\x38\x76\x27\x5bAAAAAAAAAAAAAAAAAAAAAAAAAAAPlay that funky musicAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xcc\x5c\x27\xee\x1b\x6f")
	key := []byte("\xe7\x3a\x0e\xdb\xb2\x93\x18\x59\x7e\xe1\x6a\x8b\x4f\xda\xfd\xdd")

	encrypted, err := encryptWithMode(key, plaintext, 1)
	if err != nil {
		t.Errorf("TestDetectionOracle: got an error %v", err)
		return
	}
	secondBlock := encrypted[16:32]
	thridBlockFromLast := encrypted[len(encrypted)-48 : len(encrypted)-32]

	if bytes.Compare(secondBlock, thridBlockFromLast) == 0 {
		t.Errorf("TestDetectionOracleForEcbMode: CBC mode should have different encrypted texts for same plaintexts")
	}
}
