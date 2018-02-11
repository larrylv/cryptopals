package aes

import (
	"crypto/aes"
	"math/rand"
	"time"
)

// Cipher is an interface that implements both Encrypt and Decrypt functions
type Cipher interface {
	Encrypt([]byte) []byte
	Decrypt([]byte) []byte
}

// EncryptionOracle encrypts plaintext with ECB or CBC randomly,
// key and IV (for CBC) are randomly generated.
func EncryptionOracle(plaintext []byte) ([]byte, error) {
	rand.Seed(time.Now().Unix())

	key := generateRandomBytes(aes.BlockSize)
	mode := rand.Intn(2)

	return encryptWithMode(key, plaintext, mode)
}

// mode 0 for ECB mode, 1 for CBC mode
func encryptWithMode(key []byte, plaintext []byte, mode int) ([]byte, error) {
	var cipher Cipher
	var err error

	if mode == 0 { // ECB
		cipher, err = NewAesEcbCipher(key, nil)
		if err != nil {
			return nil, err
		}
	} else { // CBC
		iv := generateRandomBytes(aes.BlockSize)
		cipher, err = NewAesCbcCipher(key, iv)
		if err != nil {
			return nil, err
		}

	}

	plaintext = mungePlaintext(plaintext)
	return cipher.Encrypt(plaintext), nil
}

func generateRandomBytes(size int) []byte {
	if size <= 0 {
		return nil
	}

	res := make([]byte, size)
	for i := 0; i < size; i++ {
		res[i] = byte(rand.Intn(256))
	}

	return res
}

func mungePlaintext(plaintext []byte) []byte {
	return append(
		generateRandomBytes(rand.Intn(6)+5),
		append(
			plaintext,
			generateRandomBytes(rand.Intn(6)+5)...,
		)...,
	)
}
