package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	expected := `SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`

	s, err := HexToBase64(`49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d`)
	if err != nil {
		t.Fatalf("HexToBase64: got an error %v\n", err)
	} else if s != expected {
		t.Fatalf("HexToBase64: expected %v, got %v\n", expected, s)
	}
}

func TestXor(t *testing.T) {
	a := `1c0111001f010100061a024b53535009181c`
	decodedA, _ := hex.DecodeString(a)
	b := `686974207468652062756c6c277320657965`
	decodedB, _ := hex.DecodeString(b)

	expected := `746865206b696420646f6e277420706c6179`
	decodedExpected, _ := hex.DecodeString(expected)

	s, err := Xor(decodedA, decodedB)
	if err != nil {
		t.Fatalf("Xor: got an error %v\n", err)
	} else if bytes.Compare(s, decodedExpected) != 0 {
		t.Fatalf("Xor: expected %s, got %s\n", expected, s)
	}
}

func TestRepeatKeyXor(t *testing.T) {
	str := "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
	key := `ICE`
	expectedEncoded := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	encoded, err := RepeatKeyXor([]byte(key), []byte(str))
	if err != nil {
		t.Fatalf("RepeatKeyXor: got an error %v\n", err)
	} else if bytes.Compare([]byte(expectedEncoded), encoded) != 0 {
		t.Fatalf("RepeatKeyXor: expected %s, got %s\n", expectedEncoded, encoded)
	}
}

func TestFindSingleKeyForXorCipher(t *testing.T) {
	a := `1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736`
	decodedA, _ := hex.DecodeString(a)
	expectedKey := "X"

	s, err := FindSingleKeyForXorCipher(decodedA)
	if err != nil {
		t.Errorf("FindSingleKeyForXorCipher: got an error %v\n", err)
	} else if string(s) != expectedKey {
		t.Errorf("FindSingleKeyForXorCipher: expected key %s, got %s\n", expectedKey, s)
	}
}

func TestDetectStringBeingXoredWithSingleKey(t *testing.T) {
	decryptedLine, err := DetectStringBeingXoredWithSingleKey("./data/set_1_challege_4.txt")
	expectedLine := "Now that the party is jumping\n"
	if err != nil {
		t.Errorf("DetectStringBeingXoredWithSingleKey: got an error %v\n", err)
	} else if expectedLine != string(decryptedLine) {
		t.Errorf("DetectStringBeingXoredWithSingleKey: expected %v, got %v\n", expectedLine, decryptedLine)
	}
}

func TestHammingDistance(t *testing.T) {
	a := "this is a test"
	b := "wokka wokka!!!"

	res := HammingDistance([]byte(a), []byte(b))
	if res != 37 {
		t.Errorf("HammingDistance: expected %d, got %d\n", 37, res)
	}
}
