package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

func TestDecryptCipherXoredByRepeatKey(t *testing.T) {
	filename := "./data/set_1_challege_6.txt"
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestDecryptCipherXoredByRepeatKey: got an error %v", err)
		return
	}

	decrypted, err := DecryptCipherXoredByRepeatKey(cipher)
	if err != nil {
		t.Errorf("TestDecryptCipherXoredByRepeatKey: got an error %v", err)
		return
	}
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestDecryptCipherXoredByRepeatKey: expected it contains %s", "Play that funky music")
	}
}
