package main

import (
	"bytes"
	"io/ioutil"
	"testing"
)

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

func TestDecryptRepeatKeyXor(t *testing.T) {
	filename := "./data/set_1_challege_6.txt"
	cipher, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestDecryptRepeatKeyXor: got an error %v", err)
		return
	}

	decrypted, err := DecryptRepeatKeyXor(cipher)
	if err != nil {
		t.Errorf("TestDecryptRepeatKeyXor: got an error %v", err)
		return
	}
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestDecryptRepeatKeyXor: expected it contains %s", "Play that funky music")
	}
}
