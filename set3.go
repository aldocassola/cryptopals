package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
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

func ctrEncrypt(pt []byte, nonce uint64, ctrStart uint64, ciph cipher.Block) []byte {
	bs := ciph.BlockSize()
	var ct []byte
	i := 0
	ctr := ctrStart
	for ; i+bs < len(pt); i, ctr = i+bs, ctr+1 {
		stream := getKeyStream(nonce, ctr, ciph)
		ct = append(ct, xor(pt[i:i+bs], stream)...)
	}

	stream := getKeyStream(nonce, ctr, ciph)
	ct = append(ct, xor(pt[i:], stream[:len(pt)-i])...)

	return ct
}

func getKeyStream(nonce, ctr uint64, ciph cipher.Block) []byte {
	n := make([]byte, 8)
	binary.LittleEndian.PutUint64(n, nonce)
	ctrBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(ctrBytes, ctr)
	block := append(n[:len(n)], ctrBytes...)
	stream := make([]byte, ciph.BlockSize())
	ciph.Encrypt(stream, block)
	return stream
}

func ctrDecrypt(ct []byte, nonce uint64, ctrStart uint64, ciph cipher.Block) []byte {
	return ctrEncrypt(ct, nonce, ctrStart, ciph)
}

func makeFixedNonceCTR() func([]byte) []byte {
	ciph := makeAES(randKey(aes.BlockSize))
	counter := uint64(0)
	return func(in []byte) []byte {
		return ctrEncrypt(in, counter, counter, ciph)
	}

}

func findFixedCTRKeystream(ciphertexts [][]byte, keyLen int, enc func([]byte) []byte, lmap langmap) ([]byte, []byte) {
	var truncatedCt []byte
	for i := range ciphertexts {
		truncatedCt = append(truncatedCt, ciphertexts[i][:keyLen]...)
	}

	return trialRepeatedXORDecrypt(truncatedCt, keyLen, lmap)
}

//MT19937w32 : Mersenne Twister type
type MT19937w32 struct {
	w, n, m, r, a, u, d, s, b, t, c, l, f uint32
	state                                 []uint32
	index                                 uint32
}

//Init : Initializes MT parameters
func (mt *MT19937w32) Init(seed uint32) {
	mt.w, mt.n, mt.m, mt.r = 32, 624, 397, 31
	mt.a = 0x9908b0df
	mt.u, mt.d = 11, 0xffffffff
	mt.s, mt.b = 7, 0x9d2c5680
	mt.t, mt.c = 15, 0xEFC60000
	mt.l = 18
	mt.f = 1812433253
	mt.state = make([]uint32, mt.n)
	mt.index = 624
	mt.state[0] = seed
	for i := 1; i < int(mt.n); i++ {
		mt.state[i] = mt.f*(mt.state[i-1]^(mt.state[i-1]>>(mt.w-uint32(2)))) + uint32(i)
	}
}

//Extract : gets next number
func (mt *MT19937w32) Extract() uint32 {
	if mt.index >= 624 {
		mt.Twist()
	}
	y := mt.state[mt.index]
	y = y ^ y>>mt.u&mt.d
	y = y ^ y<<mt.s&mt.b
	y = y ^ y<<mt.t&mt.c
	y = y ^ y>>mt.l
	mt.index++
	return y & 0xffffffff
}

//Twist : loop transform
func (mt *MT19937w32) Twist() {
	for i := 0; i < int(mt.n); i++ {
		y := uint32(mt.state[i]&0x80000000) + (mt.state[(i+1)%int(mt.n)] & 0x7fffffff)
		mt.state[i] = mt.state[(i+int(mt.m))%int(mt.n)] ^ y>>1

		if y%2 != 0 {
			mt.state[i] = mt.state[i] ^ mt.a
		}
	}
	mt.index = 0
}
