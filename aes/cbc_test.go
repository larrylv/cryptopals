package aes

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func TestAesCbcCipherEncrypt(t *testing.T) {
	plaintext := "Play that funky music"
	iv := bytes.Repeat([]byte("\x00"), aes.BlockSize)
	cipher, err := NewAesCbcCipher([]byte("YELLOW SUBMARINE"), iv)
	if err != nil {
		t.Errorf("TestDecryptAesCbcCipher: got an error %v", err)
		return
	}

	encrypted := cipher.Encrypt([]byte(plaintext))
	decrypted := cipher.Decrypt(encrypted)

	// fmt.Printf("%v - %s, %v - %s\n", plaintext, plaintext, decrypted, decrypted)
	if bytes.Compare([]byte(plaintext), decrypted) != 0 {
		t.Errorf("TestAesCbcCipherEncrypt: sth wrong with the encryption or decryption, got %s after decryption", decrypted)
	}
}

func TestAesCbcCipherDecrypt(t *testing.T) {
	filename := "../data/set_2_challege_10.txt"
	ciphertext, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestAesCbcCipherDecrypt: got an error %v", err)
		return
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		t.Errorf("TestAesCbcCipherDecrypt: %v", err)
		return
	}

	iv := bytes.Repeat([]byte("\x00"), aes.BlockSize)
	cipher, err := NewAesCbcCipher([]byte("YELLOW SUBMARINE"), iv)
	if err != nil {
		t.Errorf("TestAesCbcCipherDecrypt: got an error %v", err)
		return
	}

	decrypted := cipher.Decrypt(decodedCiphertext)
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestAesCbcCipherDecrypt: expected it contains %s", "Play that funky music")
	}
}
