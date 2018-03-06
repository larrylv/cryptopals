# the cryptopals crypto challenges (a.k.a. Matasano crypto challenges)

[![Build Status](https://circleci.com/gh/larrylv/cryptopals/tree/master.svg?style=shield&circle-token=2f0ef05b1a06905e660a9890231523430ea3b966)](https://circleci.com/gh/larrylv/cryptopals/tree/master)

* [Set 1: Basics](#set-1-basics)
* [Set 2: Block crypto](#set-2-block-crypto)

## Set 1: Basics

### Challenge 1. Convert hex to base64

http://cryptopals.com/sets/1/challenges/1

```
go test ./util/... -run='TestHexToBase64'
```

### Challenge 2. Fixed XOR

http://cryptopals.com/sets/1/challenges/2

```
go test ./util/... -run='TestXor'
```

### Challenge 3. Single-byte XOR cipher

http://cryptopals.com/sets/1/challenges/3

```
go test ./util/... -run='TestFindSingleXorByte'
```

### Challenge 4. Detect single-character XOR

http://cryptopals.com/sets/1/challenges/4

```
go test ./util/... -run='TestDetectStringXoredWithSingleKey'
```

### Challenge 5. Implement repeating-key XOR

http://cryptopals.com/sets/1/challenges/5

```
go test ./util/... -run='TestXorWithRepeatKey'
```

### Challenge 6. Break repeating-key XOR

http://cryptopals.com/sets/1/challenges/6

```
go test ./util/... -run='TestDecryptStringXoredWithRepeatKey'
```

### Challenge 7. AES in ECB mode

http://cryptopals.com/sets/1/challenges/7

```
go test ./aes/... -run='TestAesEcbCipherEncrypt'
go test ./aes/... -run='TestAesEcbCipherDecrypt'
```

### Challenge 8. Detect AES in ECB mode

http://cryptopals.com/sets/1/challenges/8

```
go test ./aes/... -run='TestIsEncryptedWithAesEcbMode'
```

## Set 2: Block crypto

### Challenge 9. Implement PKCS#7 padding

http://cryptopals.com/sets/2/challenges/9

```
go test ./util/... -run='TestPKCS7Padding'
```

### Challenge 10. Implement CBC mode

http://cryptopals.com/sets/2/challenges/10

```
go test ./aes/... -run='TestAesCbcCipherEncrypt'
go test ./aes/... -run='TestAesCbcCipherDecrypt'
```

### Challenge 11. An ECB/CBC detection oracle

http://cryptopals.com/sets/2/challenges/11

```
go test ./aes/... -run='TestDetectionOracleForEcbMode'
go test ./aes/... -run='TestDetectionOracleForCbcMode'
```

### Challenge 12. Byte-at-a-time ECB decryption (Simple)

http://cryptopals.com/sets/2/challenges/12

```
go test ./aes/... -run='TestDecryptSalt'
```

### Challenge 13. ECB cut-and-paste

http://cryptopals.com/sets/2/challenges/13

```
go test ./aes/... -run='TestEcbCutAndPaste'
```
