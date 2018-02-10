package util

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

func TestHammingDistance(t *testing.T) {
	a := "this is a test"
	b := "wokka wokka!!!"

	res := HammingDistance([]byte(a), []byte(b))
	if res != 37 {
		t.Errorf("HammingDistance: expected %d, got %d\n", 37, res)
	}
}

func TestPKCS7Padding(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	expectedCipher := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	cipher, err := PKCS7Padding([]byte(plaintext), 20)
	if err != nil {
		t.Errorf("TestPKCS7Padding: got an error %v", err)
		return
	}

	if bytes.Compare([]byte(expectedCipher), cipher) != 0 {
		t.Errorf("TestPKCS7Padding: expected %v, got %v", expectedCipher, cipher)
	}
}
