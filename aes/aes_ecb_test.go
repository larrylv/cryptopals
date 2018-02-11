package aes

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"os"
	"testing"
)

func TestAesEcbCipherEncrypt(t *testing.T) {
	plaintext := "Play that funky music"

	cipher, err := NewAesEcbCipher([]byte("YELLOW SUBMARINE"), nil)
	if err != nil {
		t.Errorf("TestDecryptAesEcbCipher: got an error %v", err)
		return
	}

	encrypted := cipher.Encrypt([]byte(plaintext))
	decrypted := cipher.Decrypt(encrypted)

	// fmt.Printf("%v - %s, %v - %s\n", plaintext, plaintext, decrypted, decrypted)
	if bytes.Compare([]byte(plaintext), decrypted) != 0 {
		t.Errorf("TestAesEcbCipherEncrypt: sth wrong with the encryption or decryption, got %s after decryption", decrypted)
	}
}

func TestAesEcbCipherDecrypt(t *testing.T) {
	filename := "../data/set_1_challege_7.txt"
	ciphertext, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Errorf("TestAesEcbCipherDecrypt: got an error %v", err)
		return
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		t.Errorf("TestAesEcbCipherDecrypt: %v", err)
		return
	}

	cipher, err := NewAesEcbCipher([]byte("YELLOW SUBMARINE"), nil)
	if err != nil {
		t.Errorf("TestAesEcbCipherDecrypt: got an error %v", err)
		return
	}

	decrypted := cipher.Decrypt(decodedCiphertext)
	// fmt.Printf("%s\n", decrypted)

	if !bytes.Contains(decrypted, []byte("Play that funky music")) {
		t.Errorf("TestAesEcbCipherDecrypt: expected it contains %s", "Play that funky music")
	}
}

func TestIsEncryptedWithAesEcbMode(t *testing.T) {
	filename := "../data/set_1_challege_8.txt"
	file, err := os.Open(filename)
	if err != nil {
		t.Errorf("TestIsEncryptedWithAesEcbMode: got an error %v", err)
		return
	}
	defer file.Close()

	var result []byte
	reader := bufio.NewReader(file)

	for {
		curLine, _, err := reader.ReadLine()
		if err != nil {
			break
		}

		curDecoded, err := hex.DecodeString(string(curLine))
		if err != nil {
			t.Errorf("TestIsEncryptedWithAesEcbMode: got an error %v", err)
			return
		}

		if IsEncryptedWithAesEcbMode(curDecoded) {
			result = make([]byte, len(curLine))
			copy(result, curLine)
			break
		}
	}

	expected := `d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a`
	if bytes.Compare(result, []byte(expected)) != 0 {
		t.Errorf("TestIsEncryptedWithAesEcbMode: expected %s, got %s\n", expected, result)
	}
}

func TestDetectBlockSize(t *testing.T) {
	encodedSalt := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	salt, _ := base64.StdEncoding.DecodeString(encodedSalt)

	key := generateRandomBytes(aes.BlockSize)
	cipher, err := NewAesEcbCipher(key, salt)
	if err != nil {
		t.Errorf("TestDetectBlockSize: got an error %v", err)
		return
	}

	keySize := cipher.(*EcbCipher).detectBlockSize()
	if keySize != aes.BlockSize {
		t.Errorf("TestDetectBlockSize: expected %d, got %d", aes.BlockSize, keySize)
	}
}

func TestDetectSaltSize(t *testing.T) {
	for expectedSaltSize := 0; expectedSaltSize < 100; expectedSaltSize += 4 {
		key := generateRandomBytes(aes.BlockSize)
		salt := generateRandomBytes(expectedSaltSize)
		cipher, err := NewAesEcbCipher(key, salt)
		if err != nil {
			t.Errorf("TestDetectBlockSize: got an error %v", err)
			return
		}

		saltSize := cipher.(*EcbCipher).detectSaltSize()
		if expectedSaltSize != saltSize {
			t.Errorf("TestDetectSaltSize: expected %d, got %d", expectedSaltSize, saltSize)
		}
	}
}

func TestDecryptSalt(t *testing.T) {
	key := generateRandomBytes(aes.BlockSize)
	encodedSalt := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	expectedSalt, _ := base64.StdEncoding.DecodeString(encodedSalt)
	cipher, err := NewAesEcbCipher(key, expectedSalt)
	if err != nil {
		t.Errorf("TestDetectBlockSize: got an error %v", err)
		return
	}

	salt := cipher.(*EcbCipher).DecryptSalt()
	if bytes.Compare(expectedSalt, salt) != 0 {
		t.Errorf("TestDecryptSalt: expected %s, got %v", expectedSalt, salt)
		return
	}
}

func TestDetectSaltByte(t *testing.T) {
	key := generateRandomBytes(aes.BlockSize)
	salt := generateRandomBytes(30)
	cipher, err := NewAesEcbCipher(key, salt)
	if err != nil {
		t.Errorf("TestDetectBlockSize: got an error %v", err)
		return
	}

	for saltIdx := 0; saltIdx < 30; saltIdx += 4 {
		blockPrefix := make([]byte, aes.BlockSize-1)
		var leftPaddedPlainText []byte
		var blockIdx int

		if saltIdx >= aes.BlockSize {
			leftPaddedPlainText = bytes.Repeat([]byte("A"), aes.BlockSize-saltIdx%aes.BlockSize-1)
			copy(blockPrefix, salt[saltIdx-aes.BlockSize+1:saltIdx])
		} else {
			leftPaddedPlainText = bytes.Repeat([]byte("A"), aes.BlockSize-saltIdx-1)
			blockPrefix = append(leftPaddedPlainText, salt[0:saltIdx]...)
		}

		blockIdx = saltIdx/aes.BlockSize + 1
		detectedByte := cipher.(*EcbCipher).detectSaltByte(blockPrefix, leftPaddedPlainText, blockIdx, aes.BlockSize)
		if detectedByte != salt[saltIdx] {
			t.Errorf("TestDetectBlockSize: expected idx %d to be %d, got %d", saltIdx, salt[saltIdx], detectedByte)
		}
	}
}
