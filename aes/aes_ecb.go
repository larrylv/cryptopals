package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/larrylv/cryptopals/util"
)

// EcbCipher is just an AES ECB mode cipher...
type EcbCipher struct {
	cipherBlock cipher.Block
	salt        []byte
	blockSize   int
}

// NewAesEcbCipher returns an AES ECB cipher
func NewAesEcbCipher(key []byte) (Cipher, error) {
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &EcbCipher{
		cipherBlock: cipherBlock,
		blockSize:   aes.BlockSize,
	}, nil
}

// SetSalt - shut up golint
func (cipher *EcbCipher) SetSalt(salt []byte) {
	cipher.salt = make([]byte, len(salt))
	copy(cipher.salt, salt)
}

// BlockEncrypt of AesEcbCipher encrypts exactly one block
func (cipher *EcbCipher) BlockEncrypt(plaintext []byte) []byte {
	if len(plaintext) != cipher.blockSize {
		return nil
	}

	encrypted := make([]byte, len(plaintext))
	cipher.cipherBlock.Encrypt(encrypted, plaintext)

	return encrypted
}

// Encrypt of AesEcbCipher implements Encrypt function of aesCipher interface
func (cipher *EcbCipher) Encrypt(plaintext []byte) []byte {
	paddedPlainText, err := util.PKCS7Padding([]byte(plaintext), cipher.blockSize)
	if err != nil {
		fmt.Errorf("AesEcbCipher.Encrypt error: %v", err)
		return nil
	}

	encrypted := make([]byte, len(paddedPlainText))
	for bs, be := 0, cipher.blockSize; be <= len(paddedPlainText); bs, be = bs+cipher.blockSize, be+cipher.blockSize {
		copy(encrypted[bs:be], cipher.BlockEncrypt(paddedPlainText[bs:be]))
	}

	return encrypted
}

// EncryptOracle of EcbCipher will append a salt string to plaintext before encrypting
func (cipher *EcbCipher) EncryptOracle(plaintext []byte) []byte {
	if cipher.salt != nil && len(cipher.salt) > 0 {
		plaintext = append(plaintext, cipher.salt...)
	}
	return cipher.Encrypt(plaintext)
}

// BlockDecrypt of AesEcbCipher decrypts exactly one block
func (cipher *EcbCipher) BlockDecrypt(ciphertext []byte) []byte {
	if len(ciphertext) != cipher.blockSize {
		return nil
	}

	decrypted := make([]byte, len(ciphertext))
	cipher.cipherBlock.Decrypt(decrypted, ciphertext)

	return decrypted
}

// Decrypt of AesEcbCipher implements Decrypt function of aesCipher interface
func (cipher *EcbCipher) Decrypt(ciphertext []byte) []byte {
	decrypted := make([]byte, len(ciphertext))
	for bs, be := 0, cipher.blockSize; be <= len(ciphertext); bs, be = bs+cipher.blockSize, be+cipher.blockSize {
		copy(decrypted[bs:be], cipher.BlockDecrypt(ciphertext[bs:be]))
	}

	if len(decrypted) > 1 {
		paddedByte := decrypted[len(decrypted)-1]
		endIdx := len(decrypted) - int(paddedByte)
		decrypted = decrypted[:endIdx]
	}

	return decrypted
}

// IsEncryptedWithAesEcbMode returns if the ciphertext is encrypted with AES in ECB mode
func IsEncryptedWithAesEcbMode(ciphertext []byte) bool {
	m := make(map[string]bool)
	blockSize := aes.BlockSize

	for i := 0; i+1 <= len(ciphertext)/blockSize; i++ {
		block := ciphertext[i*blockSize : (i+1)*blockSize]
		if m[string(block)] {
			return true
		}
		m[string(block)] = true
	}

	return false
}

// DetectBlockSize means shut up golint
func (cipher *EcbCipher) DetectBlockSize() int {
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

// DecryptSalt returns the salt that is used when encrypting
func (cipher *EcbCipher) DecryptSalt() []byte {
	blockSize := cipher.DetectBlockSize()
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
			encrypted := cipher.EncryptOracle(append(curDetectionBlock, leftPaddedPlainText...))
			if bytes.Compare(encrypted[:blockSize], encrypted[blockIdx*blockSize:(blockIdx+1)*blockSize]) == 0 {
				salt[i] = byte(b)
				break
			}
		}
	}

	return salt
}

func (cipher *EcbCipher) detectSaltSize() int {
	saltSize := 0
	blockSize := cipher.DetectBlockSize()
	prevEncryptedSize := len(cipher.EncryptOracle([]byte("")))

	for i := 1; i <= blockSize; i++ {
		curEncryptedSize := len(cipher.EncryptOracle(bytes.Repeat([]byte("A"), i)))
		if curEncryptedSize == prevEncryptedSize+blockSize {
			saltSize = prevEncryptedSize - i
			break
		}
	}

	return saltSize
}
