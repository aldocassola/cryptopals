package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	mathrand "math/rand"
	"strings"
	"time"
	"unicode"
)

type decryptionOracle func(in, iv []byte) bool

func makeCBCPaddingOracle() (func() ([]byte, []byte), decryptionOracle) {
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

func decryptWithCBCPaddingOracle(ct []byte, iv []byte, checkPadding decryptionOracle) []byte {
	bs := aes.BlockSize
	zeros := bytes.Repeat([]byte{'\x00'}, bs)

	// discover i-th byte in curBlock using checkPadding and prevBlock
	findByte := func(i int, prevBlock, curBlock, pt []byte) byte {
		if i >= bs {
			panic("findByte: invalid block index")
		}

		if len(prevBlock) != bs || len(curBlock) != bs {
			panic("findByte: invalid block sizes")
		}

		padBytes := pkcs7Pad(zeros[:i], bs)

		// guess current byte
		// then xor previous block with expected pad and byte guess
		for b := 0; b < 256; b++ {
			mangler := xor(pt, padBytes)
			mangler[i] ^= byte(b)

			// doing nothing to the IV gives no useful info right now
			// check this at the end
			if bytes.Equal(zeros, mangler) {
				continue
			}

			// if the padding is valid, we know our guess is correct
			// by virtue of CBC
			if checkPadding(curBlock, xor(prevBlock, mangler)) {
				return byte(b)
			}
		}

		// if the only one that works is doing nothing
		// we know we have a full pkcs7 pad
		return byte(bs - i)
	}

	// concatenate iv and ciphertext
	ct2 := make([]byte, len(ct)+bs)
	copy(ct2, iv)
	copy(ct2[bs:], ct)

	known := make([]byte, len(ct))
	plaintext := make([]byte, bs)

	// loop backwards through the blocks, guessing each byte
	for i := len(ct2) - 1; i >= bs; i-- {
		blockStart := i - i%bs
		prevBlock := ct2[blockStart-bs : blockStart]
		curBlock := ct2[blockStart : blockStart+bs]
		plaintext[i%bs] = findByte(i%bs, prevBlock, curBlock, plaintext)

		//once we have a full block, copy to known and reinitialize blocks
		if i%bs == 0 {
			copy(known[i-bs:i], plaintext)
			plaintext = make([]byte, bs)
		}
	}

	return known
}

func ctrEncrypt(pt []byte, nonce uint64, ctrStart uint64, ciph cipher.Block) []byte {
	bs := ciph.BlockSize()
	iv := make([]byte, 16)
	binary.LittleEndian.PutUint64(iv[:8], nonce)
	binary.LittleEndian.PutUint64(iv[8:], ctrStart)
	ct := make([]byte, len(pt))
	i := 0
	for ; i < len(pt); i += bs {
		stream := getKeyStream(iv, ciph)
		copy(ct[i:], xor(pt[i:], stream))
		ctrIncrement(iv[8:])
	}

	return ct
}

func ctrIncrement(ctr []byte) {
	i := 0
	for i < len(ctr) {
		ctr[i]++
		if ctr[i] != 0 {
			break
		}
		i++
	}
}

func getKeyStream(block []byte, ciph cipher.Block) []byte {
	return ecbEncrypt(block, ciph)
}

func ctrDecrypt(ct []byte, nonce, ctr uint64, ciph cipher.Block) []byte {
	return ctrEncrypt(ct, nonce, ctr, ciph)
}

func makeFixedNonceCTR() func([]byte) []byte {
	ciph := makeAES(randKey(aes.BlockSize))
	counter := uint64(0)
	return func(in []byte) []byte {
		return ctrEncrypt(in, counter, counter, ciph)
	}

}

func fixedCTRNonceKey(data [][]byte, engMap langmap) []byte {
	var key []byte

	englishUpper := make(langmap)

	for ch, freq := range engMap {
		if unicode.IsUpper(ch) {
			englishUpper[ch] = freq
		}
	}

	for col := 0; ; col++ {
		var column []byte

		for row := range data {
			if col >= len(data[row]) {
				continue
			}

			column = append(column, data[row][col])
		}

		if len(column) < 2 {
			break
		}

		var m langmap
		if col == 0 {
			m = englishUpper
		} else {
			m = engMap
		}
		k, _, _ := findSingleKeyXor(column, m)
		key = append(key, k)
	}

	return key
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
	for i := uint32(1); i < mt.n(); i++ {
		mt.state[i] = mt.f()*(mt.state[i-1]^(mt.state[i-1]>>(mt.w()-uint32(2)))) + i
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
	return time.Duration(40+mathrand.Intn(961)) * time.Millisecond
}

func runMT19937WithDelay() uint32 {
	time.Sleep(randDuration())
	mt := new(MT19937w32)
	mt.Init(uint32(time.Now().UnixNano() / int64(time.Millisecond)))
	time.Sleep(randDuration())
	return mt.Extract()
}

func getMT19937Seed(output uint32) uint32 {
	t := uint32(time.Now().UnixNano() / int64(time.Millisecond))
	for {
		mt := new(MT19937w32)
		mt.Init(t)
		if mt.Extract() == output {
			return t
		}
		t--
	}
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

func mtEncrypt(in []byte, key uint16) []byte {
	ks := getMT19937KeyStream(uint32(len(in)), uint32(key))
	return xor(in, ks)
}

func mtDecrypt(in []byte, key uint16) []byte {
	return mtEncrypt(in, key)
}

func getMT19937KeyStream(length, key uint32) []byte {
	mt := new(MT19937w32)
	mt.Init(key)
	ks := make([]byte, length+4)
	for index := uint32(0); index < length; index += 4 {
		elem := mt.Extract()
		ks[index] = byte(elem)
		ks[index+1] = byte(elem >> 8)
		ks[index+2] = byte(elem >> 16)
		ks[index+3] = byte(elem >> 24)
	}
	return ks[:length]
}

func getMT19937EncryptPrefixOracle() oracle {
	n := randKey(2)
	seed := uint16(n[0]) + uint16(n[1])<<8
	numbytes := 5 + mathrand.Intn(95)
	prefix := make([]byte, numbytes)
	rand.Read(prefix)
	return func(in []byte) []byte {
		pt := make([]byte, len(prefix))
		pt = append(pt, in...)
		return mtEncrypt(pt, seed)
	}
}

func getMT19937SeedFromCT(suffix, ct []byte) int {

	for s := 0; s < 0x10000; s++ {
		keystream := getMT19937KeyStream(uint32(len(ct)), uint32(s))
		trial := xor(ct, keystream)
		if bytes.HasSuffix(trial, suffix) {
			return s
		}
	}
	return -1
}

func getMT19937ResetPwdToken(length uint32) string {
	seed := uint32(time.Now().Unix())
	ks := getMT19937KeyStream(length, seed)
	return base64Encode(ks)
}

func isMT19937Token(tok string) bool {
	start := uint32(time.Now().Unix())
	ks := base64Decode(tok)

	for t := uint32(0); t < 60*60*24; t++ {
		testks := getMT19937KeyStream(uint32(len(ks)), start-t)
		if bytes.Equal(ks, testks) {
			return true
		}
	}
	return false
}
