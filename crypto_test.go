package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestDecryptAesEcbCipher(t *testing.T) {
	filename := "./data/set_1_challege_7.txt"
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestDecryptAesEcbCipher: got an error %v", err)
		return
	}

	key := []byte("YELLOW SUBMARINE")
	decrypted, err := DecryptAesEcbCipher(key, cipher)
	if err != nil {
		t.Errorf("TestDecryptAesEcbCipher: got an error %v", err)
		return
	}
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestDecryptAesEcbCipher: expected it contains %s", "Play that funky music")
	}
}

func TestPkcs7Padding(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	expectedCipher := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	cipher, err := Pkcs7Padding([]byte(plaintext), 20)
	if err != nil {
		t.Errorf("TestPkcs7Padding: got an error %v", err)
		return
	}

	if bytes.Compare([]byte(expectedCipher), cipher) != 0 {
		t.Errorf("TestPkcs7Padding: expected %v, got %v", expectedCipher, cipher)
	}
}
