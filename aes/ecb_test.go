package aes

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/larrylv/cryptopals/util"
)

func TestAesEcbCipherEncrypt(t *testing.T) {
	plaintext := "Play that funky music"

	cipher, err := NewAesEcbCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Errorf("TestDecryptAesEcbCipher: got an error %v", err)
		return
	}

	encrypted := cipher.Encrypt([]byte(plaintext))
	decrypted := cipher.Decrypt(encrypted)

	// fmt.Printf("%v - %s, %v - %s\n", plaintext, plaintext, decrypted, decrypted)
	if !bytes.Equal([]byte(plaintext), decrypted) {
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

	cipher, err := NewAesEcbCipher([]byte("YELLOW SUBMARINE"))
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
	if !bytes.Equal(result, []byte(expected)) {
		t.Errorf("TestIsEncryptedWithAesEcbMode: expected %s, got %s\n", expected, result)
	}
}

func TestEcbCutAndPaste(t *testing.T) {
	key := generateRandomBytes(aes.BlockSize)
	cipher, err := NewAesEcbCipher(key)
	if err != nil {
		t.Errorf("TestEcbCutAndPaste: got an error %v", err)
		return
	}

	// build an whole block with `email=AAA...`
	adminEmail := bytes.Repeat([]byte("A"), aes.BlockSize-len("email="))
	padded, _ := util.PKCS7Padding([]byte("admin"), aes.BlockSize)
	adminEmail = append(adminEmail, padded...)
	// Encryption text of `admin` with appended padding text will be the second block
	adminEncrypted := cipher.Encrypt(profileFor(adminEmail))[aes.BlockSize : aes.BlockSize*2]

	// first two blocks would be: `email=A...&uid=10&role=`
	detectionEmail := bytes.Repeat([]byte("A"), aes.BlockSize-len("email=&uid=10&role=")%aes.BlockSize)
	detectionEncrypted := cipher.Encrypt(profileFor(detectionEmail))[:aes.BlockSize*2]

	expectedProfile := []byte("email=AAAAAAAAAAAAA&uid=10&role=admin")
	decryptedProfile := cipher.Decrypt(append(detectionEncrypted, adminEncrypted...))
	if !bytes.Equal(expectedProfile, decryptedProfile) {
		t.Errorf("TestEcbCutAndPaste: expected %s, got %s", expectedProfile, decryptedProfile)
	}
}

// I didn't do any escape for email, but in real world, we should
func profileFor(email []byte) []byte {
	return []byte(fmt.Sprintf("email=%s&uid=10&role=user", string(email)))
}
