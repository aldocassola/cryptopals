package cryptopals

import (
	"bytes"
	"crypto/aes"
	mathrand "math/rand"
	"strings"
	"time"
)

type paddingOracle func([]byte, []byte) bool

func makeCBCPaddingOracle() (func() ([]byte, []byte), paddingOracle) {
	mathrand.Seed(time.Now().UTC().UnixNano())
	myStrings := strings.Fields(`MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
		MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
		MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
		MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
		MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
		MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
		MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
		MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
		MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
		MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93`)
	choice := myStrings[mathrand.Intn(len(myStrings))]
	aesKey := randKey(aes.BlockSize)
	ciph := makeAES(aesKey)
	encryptor := func() ([]byte, []byte) {
		padded := pkcs7Pad([]byte(choice), aes.BlockSize)
		iv := randKey(aes.BlockSize)
		return cbcEncrypt(padded, iv, ciph), iv
	}
	isValidPadding := func(ct []byte, iv []byte) bool {
		_, err := pkcs7Unpad(cbcDecrypt(ct, iv, ciph))
		return err == nil
	}
	return encryptor, isValidPadding
}

func decryptWithCBCPaddingOracle(ct []byte, iv []byte, oracle paddingOracle) []byte {
	var known [][]byte
	bs := aes.BlockSize
	zeros := bytes.Repeat([]byte{'\x00'}, bs)
	ctcopy := make([]byte, len(ct)+bs)
	copy(ctcopy, iv)
	copy(ctcopy[bs:], ct)
	thisBlock := make([]byte, bs)
	for i := len(ctcopy) - bs - 1; i >= 0; i-- {
		blockStart := i - i%bs
		padByte := byte(bs - i%bs)
		//guess current byte
		for b := 0; b < 256; b++ {
			thisBlock[i%bs] = byte(b)
			padBytes := bytes.Repeat([]byte{padByte}, int(padByte))
			padBytes = append(zeros[:bs], padBytes...)[len(padBytes):]
			mangler := xor(thisBlock, padBytes)
			if i%bs == 15 && bytes.Equal(mangler, zeros) {
				continue
			}
			mangled := xor(mangler, ctcopy[blockStart:blockStart+bs])
			copy(ctcopy[blockStart:blockStart+bs], mangled)
			isValid := oracle(ctcopy[:blockStart+2*bs], iv)
			var toRestore []byte
			if i >= bs {
				toRestore = ct[blockStart-bs : blockStart]
			} else {
				toRestore = iv
			}
			copy(ctcopy[blockStart:blockStart+bs], toRestore)
			if isValid == true {
				break
			}
		}
		//once we have a full block, copy to known and reinitialize blocks
		if i%bs == 0 {
			known = append(known, thisBlock)
			thisBlock = make([]byte, bs)

		}
	}

	var result []byte
	for i := range known {
		result = append(result, known[len(known)-i-1]...)
	}
	return result
}
