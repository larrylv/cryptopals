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
