package util

import (
	"encoding/hex"
	"testing"
)

func TestFindSingleXorByte(t *testing.T) {
	a := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
	decodedA, _ := hex.DecodeString(a)
	expectedKey := "X"

	s, err := FindSingleXorByte(decodedA)
	if err != nil {
		t.Errorf("FindSingleXorByte: got an error %v\n", err)
	} else if string(s) != expectedKey {
		t.Errorf("FindSingleXorByte: expected key %s, got %s\n", expectedKey, []byte{s})
	}
}

func TestDetectStringXoredWithSingleKey(t *testing.T) {
	decryptedLine, err := DetectStringXoredWithSingleKey("../data/set_1_challege_4.txt")
	expectedLine := "Now that the party is jumping\n"
	if err != nil {
		t.Errorf("DetectStringXoredWithSingleKey: got an error %v\n", err)
	} else if expectedLine != string(decryptedLine) {
		t.Errorf("DetectStringXoredWithSingleKey: expected %v, got %v\n", expectedLine, decryptedLine)
	}
}
