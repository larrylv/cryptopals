package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestDecryptRepeatKeyXorCipher(t *testing.T) {
	filename := "./data/set_1_challege_6.txt"
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestDecryptRepeatKeyXorCipher: got an error %v", err)
		return
	}

	decrypted, err := DecryptRepeatKeyXorCipher(cipher)
	if err != nil {
		t.Errorf("TestDecryptRepeatKeyXorCipher: got an error %v", err)
		return
	}
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestDecryptRepeatKeyXorCipher: expected it contains %s", "Play that funky music")
	}
}

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
