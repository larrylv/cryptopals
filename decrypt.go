package main

import (
	"fmt"
	"math"
)

// DecryptCipherXoredByRepeatKey decrypts the cipher which the original
// string is xor'ed by repeat-key
func DecryptCipherXoredByRepeatKey(cipher []byte) []byte {
	keySize := FindRepeatKeySize(cipher)
	fmt.Printf("%d\n", keySize)

	return []byte("wtf")
}

// FindRepeatKeySize returns the most possible repeat-key size for the cipher
func FindRepeatKeySize(cipher []byte) int {
	keySize := 0
	minDistance := math.Inf(1)

	for i := 2; i <= 64; i++ {
		// exceeds the cipher length
		if 2*i > len(cipher) {
			break
		}

		distance := 0.0
		cnt := 0

		for j := 0; j < 3 && (j+2)*i <= len(cipher); j++ {
			distance += float64(HammingDistance(cipher[j*i:(j+1)*i], cipher[(j+1)*i:(j+2)*i]))
			cnt++
		}

		distance /= float64(cnt * i)

		if distance < minDistance {
			keySize = i
			minDistance = distance
		}
	}

	return keySize
}
