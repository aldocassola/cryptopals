package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
)

func hexToBase64(in string) string {
	return base64.StdEncoding.EncodeToString(hexDecode(in))
}

func hexDecode(hs string) []byte {
	res, err := hex.DecodeString(hs)
	if err != nil {
		panic("hexDecode: invalid hex string")
	}
	return res
}

func xor(s, t []byte) []byte {

	if len(s) > len(t) {
		s = s[:len(t)]
	}

	res := make([]byte, len(s))

	for i := range s {
		res[i] = s[i] ^ t[i]
	}
	return res
}

type langmap map[rune]float64

func makeLangMap(text string) langmap {
	lmap := make(langmap)

	for _, r := range text {
		lmap[r]++
	}

	for r := range lmap {
		lmap[r] /= float64(len(text))
	}

	return lmap
}

func scoreLanguage(text string, lmap langmap) float64 {
	result := float64(0)
	for _, r := range text {
		result += lmap[r]
	}

	return result / float64(len(text))
}

func findSingleKeyXor(ctbytes []byte, lmap langmap) (key byte, pt string, highest float64) {
	for testKey := 0; testKey < 256; testKey++ {
		keyBuf := bytes.Repeat([]byte{byte(testKey)}, len(ctbytes))
		testpt := string(xor(ctbytes, keyBuf))

		curScore := scoreLanguage(testpt, lmap)
		if curScore > highest {
			highest = curScore
			key = byte(testKey)
			pt = testpt
		}
	}
	return
}
