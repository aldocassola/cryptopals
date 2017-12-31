package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"math/big"
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

	//tempering -- this is reversible
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
	mt := new(MT19937w32)
	// revert y = y ^ y>>mt.l()
	y3 := (y & 0xffffc000)
	y3 |= ((y >> mt.l()) ^ (y & 0x3fff))

	// revert y = y ^ y<<mt.t()&mt.c()
	y2 := (y3 & 0x1039ffff)
	y2 |= ((y3 ^ ((y2 << mt.t()) & mt.c())) & 0xfffe0000)

	// revert y = y ^ y<<mt.s()&mt.b()
	y1 := y2 & 0x7f
	for shift := uint(7); shift < 29; shift += 7 {
		y1 |= ((((y1 << mt.s()) & mt.b()) ^ y2) & (0x7f << shift))
	}

	// revert y = y ^ y>>mt.u()&mt.d()
	y0 := (y1 & 0xffe00000)
	y0 |= (((y0 >> mt.u()) ^ y1) & 0x001ffc00)
	y0 |= (((y0 >> mt.u()) ^ y1) & 0x3ff)

	return y0
}

func mtEncrypt(in []byte, mt *MT19937w32) []byte {
	ks := make([]byte, len(in))
	getMT19937KeyStream(ks, mt)
	return xor(in, ks)
}

func mtDecrypt(in []byte, mt *MT19937w32) []byte {
	return mtEncrypt(in, mt)
}

func getMT19937KeyStream(ks []byte, mt *MT19937w32) {
	for index := 0; index < len(ks); index++ {
		ks[index] = byte(mt.Extract() & 0xff)
	}
}

func getMT19937EncryptPrefixOracle() oracle {
	n := big.NewInt(0)
	n = n.SetBytes(randKey(2))
	seed := uint16(n.Uint64())
	mt := new(MT19937w32)
	mt.Init(uint32(seed))
	numbytes := 5 + mathrand.Intn(95)
	prefix := make([]byte, numbytes)
	rand.Read(prefix)
	return func(in []byte) []byte {
		pt := make([]byte, len(prefix))
		pt = append(pt, in...)
		return mtEncrypt(pt, mt)
	}
}

func getMT19937SeedFromCT(pt, ct []byte) int {
	payloadLen := len(ct) - len(pt)
	keystream := xor(pt, ct[payloadLen:])
	mt := new(MT19937w32)
	found := false
	var s int
	for s = 0; s < 0x10000; s++ {
		mt.Init(uint32(s))
		for i := 0; i < payloadLen; i++ {
			mt.Extract()
		}
		var i int
		for i = 0; i < len(pt); i++ {
			if byte(mt.Extract()) != keystream[i] {
				break
			}
		}
		if i == len(pt) {
			found = true
			break
		}
	}
	var result int
	if found == true {
		result = s
	} else {
		result = -1
	}
	return result
}

func getMT19937ResetPwdToken(len int) string {
	mt := new(MT19937w32)
	mt.Init(uint32(time.Now().Unix()))
	ks := make([]byte, len)
	getMT19937KeyStream(ks, mt)
	return base64Encode(ks)
}

func isMT19937Token(tok string, start, stop int64) bool {
	ks := base64Decode(tok)
	testks := make([]byte, len(ks))
	mt := new(MT19937w32)
	for t := uint32(start); t <= uint32(stop); t++ {
		mt.Init(t)
		getMT19937KeyStream(testks, mt)
		if bytes.Equal(ks, testks) {
			return true
		}
	}
	return false
}
