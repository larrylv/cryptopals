package aes

import (
	"bytes"
	"crypto/aes"
)

// EcbOracleCipher is an enhanced EcbCipher which inserts bytes around plaintext before encrypting
type EcbOracleCipher struct {
	ecb     *EcbCipher
	prefix  []byte
	postfix []byte
}

// NewAesEcbOracleCipher shut up goling
func NewAesEcbOracleCipher(key, prefix, postfix []byte) (*EcbOracleCipher, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &EcbOracleCipher{
		ecb:     &EcbCipher{cipherBlock: cipherBlock, blockSize: aes.BlockSize},
		prefix:  prefix,
		postfix: postfix,
	}, nil
}

// Encrypt inserts bytes around plaintext and then encrypts
func (cipher *EcbOracleCipher) Encrypt(plaintext []byte) []byte {
	if cipher.prefix != nil && len(cipher.prefix) > 0 {
		plaintext = append(cipher.prefix, plaintext...)
	}
	if cipher.postfix != nil && len(cipher.postfix) > 0 {
		plaintext = append(plaintext, cipher.postfix...)
	}
	return cipher.ecb.Encrypt(plaintext)
}

// DecryptSalt returns the salt that is used when encrypting
func (cipher *EcbOracleCipher) DecryptSalt() []byte {
	blockSize := cipher.detectBlockSize()
	saltSize := cipher.detectSaltSize()

	salt := make([]byte, saltSize)
	var leftPaddedPlainText []byte
	curDetectionBlockPrefix := make([]byte, blockSize-1)

	for i := 0; i < saltSize; i++ {
		// padding some text in front so that current salt byte is the last byte of `blockIdx` block
		leftPaddedPlainText = bytes.Repeat([]byte("A"), blockSize-i%blockSize-1)
		// current salt byte is in the `blockIdx` block
		blockIdx := i/blockSize + 1
		if i >= blockSize {
			copy(curDetectionBlockPrefix, salt[i-blockSize+1:i])
		} else {
			curDetectionBlockPrefix = append(leftPaddedPlainText, salt[0:i]...)
		}

		for b := 0; b < 256; b++ {
			curDetectionBlock := append(curDetectionBlockPrefix, byte(b))
			encrypted := cipher.Encrypt(append(curDetectionBlock, leftPaddedPlainText...))
			if bytes.Compare(encrypted[:blockSize], encrypted[blockIdx*blockSize:(blockIdx+1)*blockSize]) == 0 {
				salt[i] = byte(b)
				break
			}
		}
	}

	return salt
}

func (cipher *EcbOracleCipher) detectBlockSize() int {
	var keySize int

	for i := 1; i <= 128; i++ {
		firstEncrypted := cipher.Encrypt(bytes.Repeat([]byte("A"), i))
		secondEncrypted := cipher.Encrypt(bytes.Repeat([]byte("A"), i*2))
		if bytes.Compare(firstEncrypted[:i], secondEncrypted[:i]) == 0 {
			keySize = i
			break
		}
	}

	return keySize
}

func (cipher *EcbOracleCipher) detectSaltSize() int {
	saltSize := 0
	blockSize := cipher.detectBlockSize()
	prevEncryptedSize := len(cipher.Encrypt([]byte("")))

	for i := 1; i <= blockSize; i++ {
		curEncryptedSize := len(cipher.Encrypt(bytes.Repeat([]byte("A"), i)))
		if curEncryptedSize == prevEncryptedSize+blockSize {
			saltSize = prevEncryptedSize - i
			break
		}
	}

	return saltSize
}
