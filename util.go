package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
)

// HexToBase64 converts a hex string to base64 encoded string
func HexToBase64(s string) (string, error) {
	decoded, err := hex.DecodeString(s)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(decoded), nil
}

// Xor takes two strings and returns their XOR combination
func Xor(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("byte arrays have different length")
	}

	n := len(a)
	dst := make([]byte, n)

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return dst, nil
}

// HammingDistance returns Hamming distance of two strings, which is the number of differing bits
func HammingDistance(a, b []byte) int {
	var dis int
	var minLen int

	if len(a) > len(b) {
		minLen = len(b)
		dis = len(a) - len(b)
	} else {
		minLen = len(a)
		dis = len(b) - len(a)
	}

	for i := 0; i < minLen; i++ {
		dis += bits.OnesCount(uint(a[i] ^ b[i]))
	}

	return dis
}

// PKCS7Padding implements PCKS#7 padding
func PKCS7Padding(plaintext []byte, blockSize int) ([]byte, error) {
	if blockSize > 255 || blockSize <= 0 {
		return nil, fmt.Errorf("PKCS7Padding: invalid blockSize %d", blockSize)
	}

	paddedCnt := blockSize - (len(plaintext) % blockSize)
	paddedByte := byte(paddedCnt)

	paddedText := append(plaintext, bytes.Repeat([]byte{paddedByte}, paddedCnt)...)

	return paddedText, nil
}
