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

//MT : Mersenne Twister interface
type MT interface {
	w() uint32
	n() uint32
	m() uint32
	r() uint32
	a() uint32
	u() uint32
	d() uint32
	s() uint32
	b() uint32
	t() uint32
	c() uint32
	l() uint32
	f() uint32
	Init(interface{})
	Extract() interface{}
}

//MT19937w32 : Mersenne Twister type
type MT19937w32 struct {
	state []uint32
	index uint32
}

//Init : Initializes MT parameters
func (mt *MT19937w32) Init(inseed interface{}) {
	seed, ok := inseed.(uint32)
	if !ok {
		panic("MT19937w32: seed must be an uint32")
	}
	mt.state = make([]uint32, mt.n())
	mt.index = 624
	mt.state[0] = seed
	for i := 1; i < int(mt.n()); i++ {
		mt.state[i] = mt.f()*(mt.state[i-1]^(mt.state[i-1]>>(mt.w()-uint32(2)))) + uint32(i)
	}
}

func (mt *MT19937w32) w() uint32 { return 32 }
func (mt *MT19937w32) n() uint32 { return 624 }
func (mt *MT19937w32) m() uint32 { return 397 }
func (mt *MT19937w32) r() uint32 { return 31 }
func (mt *MT19937w32) a() uint32 { return 0x9908b0df }
func (mt *MT19937w32) u() uint32 { return 11 }
func (mt *MT19937w32) d() uint32 { return 0xffffffff }
func (mt *MT19937w32) s() uint32 { return 7 }
func (mt *MT19937w32) b() uint32 { return 0x9d2c5680 }
func (mt *MT19937w32) t() uint32 { return 15 }
func (mt *MT19937w32) c() uint32 { return 0xefc60000 }
func (mt *MT19937w32) l() uint32 { return 18 }
func (mt *MT19937w32) f() uint32 { return 1812433253 }

//Extract : gets next number
func (mt *MT19937w32) Extract() uint32 {
	if mt.index >= 624 {
		mt.Twist()
	}
	y := mt.state[mt.index]
	y = y ^ y>>mt.u()&mt.d()
	y = y ^ y<<mt.s()&mt.b()
	y = y ^ y<<mt.t()&mt.c()
	y = y ^ y>>mt.l()
	mt.index++
	return y
}

//Twist : loop transform
func (mt *MT19937w32) Twist() {
	for i := 0; i < int(mt.n()); i++ {
		y := uint32(mt.state[i]&0x80000000) + (mt.state[(i+1)%int(mt.n())] & 0x7fffffff)
		mt.state[i] = mt.state[(i+int(mt.m()))%int(mt.n())] ^ y>>1

		if y%2 != 0 {
			mt.state[i] = mt.state[i] ^ mt.a()
		}
	}
	mt.index = 0
}

func randDuration() time.Duration {
	return time.Duration(40+mathrand.Intn(960)) * time.Second
}

func runMT19937WithDelay() uint32 {
	time.Sleep(randDuration())
	mt := new(MT19937w32)
	mt.Init(uint32(time.Now().Unix()))
	time.Sleep(randDuration())
	return mt.Extract()
}

func getMT19937Seed(output uint32, startTime, stopTime int64) uint32 {
	for t := startTime; t < stopTime; t++ {
		mt := new(MT19937w32)
		mt.Init(uint32(t))
		if mt.Extract() == output {
			return uint32(t)
		}
	}
	return 0
}

func untemper(y uint32) uint32 {
	// y := y3 xor (right shift by 18 bits(y3))
	// thus, high 18 bits(y3) = high 18 bits (y)
	y3 := (y & 0xffffc000)
	// low 14 = (high 14 >> 18) ^ low 14
	y3 |= ((y >> 18) ^ (y & 0x3fff))
	// y3 := y2 xor (left shift by 15 bits(y2) and (4022730752)) // 0xefc60000
	// bits not masked by xor carry over from y2 to y3 and vice-versa
	y2 := (y3 & 0x1039ffff)
	// now know the low 17 bits of y2, so strip off the xor
	y2 |= ((y3 ^ ((y2 << 15) & 0xefc60000)) & 0xfffe0000)
	// y2 := y1 xor (left shift by 7 bits(y1) and (2636928640)) // 0x9d2c5680
	// Bits 0-6 carry over:
	y1 := y2 & 0x7f
	// recover bits 7-13 by masking off xor of 0-6
	y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 7))
	// recover bits 14-20 by maksing off xor of 7-13
	y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 14))
	// recover bits 21-27 by masking off xor of 14-20
	y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & (0x7f << 21))
	// recover bits 28-31 by masking off xor if bits 21-24
	y1 |= ((((y1 << 7) & 0x9d2c5680) ^ y2) & 0xf0000000)
	// y1 := y0 xor (right shift by 11 bits(y0))
	// high 11 bits carry over:
	y0 := (y1 & 0xffe00000)
	// recover next 11 bits
	y0 |= (((y0 >> 11) ^ y1) & 0x001ffc00)
	// recover last 10
	y0 |= (((y0 >> 11) ^ y1) & 0x3ff)

	return y0
}
