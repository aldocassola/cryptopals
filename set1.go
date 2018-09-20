package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"log"
	"math"
	"math/bits"
	"sort"
	"strings"
)

func flattenStr(strs string) string {
	fields := strings.Fields(strs)
	str := ""
	for _, v := range fields {
		str += v
	}
	return str
}

func hexToBase64(in string) string {
	return base64.StdEncoding.EncodeToString(hexDecode(in))
}

func hexDecode(hs string) []byte {
	str := flattenStr(hs)
	res, err := hex.DecodeString(str)
	if err != nil {
		panic("hexDecode: invalid hex string")
	}
	return res
}

func hexEncode(in []byte) string {
	return hex.EncodeToString(in)
}

func base64Decode(b64 string) []byte {
	res, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		panic("base64Decode: wrong input string")
	}

	return res
}

func base64Encode(in []byte) string {
	return base64.StdEncoding.EncodeToString(in)
}

func xor(plain, k []byte) []byte {
	minlen := int(math.Min(float64(len(plain)), float64(len(k))))
	res := make([]byte, minlen)
	for i, b := range plain[:minlen] {
		res[i] = b ^ k[i]
	}
	return res
}

func readFile(filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic("readFile: " + err.Error())
	}
	return data
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

func findSingleKeyXor(ctbytes []byte, lmap langmap) (key byte, pt []byte, highest float64) {
	for testKey := 0; testKey < 256; testKey++ {
		keyBuf := bytes.Repeat([]byte{byte(testKey)}, len(ctbytes))
		testpt := xor(ctbytes, keyBuf)

		curScore := scoreLanguage(string(testpt), lmap)
		if curScore > highest {
			highest = curScore
			key = byte(testKey)
			pt = testpt
		}
	}
	return
}

func detectSingleKeyXor(lines []string, lMap langmap) (linenum int, pt []byte) {
	highest := float64(0)

	linenum = int(0)
	for i, ln := range lines {
		_, testpt, testscore := findSingleKeyXor(hexDecode(ln), lMap)

		if testscore > highest {
			pt = testpt
			highest = testscore
			linenum = i
		}
	}
	return
}

//XorEncrypt : []byte x []byte -> []byte
// Encrypts with repeating Xor key
func XorEncrypt(in, key []byte) []byte {
	return repeatingXor(in, key)
}

func repeatingXor(in, key []byte) []byte {
	if len(key) > len(in) {
		key = key[:len(in)]
	}

	localKey := bytes.Repeat(key, (len(in)+len(key)-1)/len(key))
	localKey = localKey[:len(in)]
	return xor(in, localKey)

}

func hammingDistance(a, b []byte) int {
	if len(a) != len(b) {
		panic("hammingDistance: mismatched lengths")
	}

	xored := xor(a, b)
	n := 0
	for _, v := range xored {
		n += bits.OnesCount8(v)
	}

	return n
}

type node struct {
	keyLen int
	weight float64
}

type byWeight []node

func (a byWeight) Len() int           { return len(a) }
func (a byWeight) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a byWeight) Less(i, j int) bool { return a[i].weight < a[j].weight }

func findSmallestKeyLengthWeights(howmany, maxKeySize int, data []byte) []node {
	dists := make([]node, maxKeySize-1)
	nBlocks := int(math.Min(20, float64(len(data)/maxKeySize)))
	for KEYSIZE := 2; KEYSIZE <= maxKeySize; KEYSIZE++ {
		block1 := data[:KEYSIZE*nBlocks]
		block2 := data[KEYSIZE*nBlocks : KEYSIZE*nBlocks*2]
		dists[KEYSIZE-2] = node{KEYSIZE, float64(hammingDistance(block1, block2)) / float64(KEYSIZE*nBlocks)}
	}

	sort.Sort(byWeight(dists))
	dists = dists[:howmany]
	return dists
}

func trialRepeatedXORDecrypt(data []byte, keyLen int, engMap langmap) (key, pt []byte) {
	numrows := (len(data) + keyLen - 1) / keyLen
	column := make([]byte, numrows)
	key = make([]byte, keyLen)
	for col := 0; col < keyLen; col++ {
		for row := range column {
			idx := row*keyLen + col
			if idx >= len(data) {
				continue
			}
			column[row] = data[idx]
		}
		key[col], _, _ = findSingleKeyXor(column, engMap)
	}
	pt = repeatingXor(data, key)
	return
}

func findRepeatedKeyXor(data []byte, engMap langmap, smallestLimit, maxKeySize int) (key, pt []byte) {
	candidates := findSmallestKeyLengthWeights(smallestLimit, maxKeySize, data)

	log.Printf("candidates: %+v", candidates)
	highest := float64(0)
	var bestKey, bestPt []byte
	for _, val := range candidates {
		key, pt := trialRepeatedXORDecrypt(data, val.keyLen, engMap)

		score := scoreLanguage(string(pt), engMap)
		if score > highest {
			highest = score
			bestKey = key
			bestPt = pt
		}
	}

	return bestKey, bestPt
}

func ecbProcessBlocks(in []byte, ciph cipher.Block, isDecryption bool) []byte {
	bs := ciph.BlockSize()
	if len(in)%bs != 0 {
		panic("Mismatched input size")
	}

	out := make([]byte, len(in))
	for i := 0; i < len(in); i += ciph.BlockSize() {
		if isDecryption {
			ciph.Decrypt(out[i:], in[i:])
		} else {
			ciph.Encrypt(out[i:], in[i:])
		}
	}

	return out
}

func ecbDecrypt(ct []byte, ciph cipher.Block) []byte {
	return ecbProcessBlocks(ct, ciph, true)
}

func detectECB(in []byte, blockSize int) (bool, int) {
	seen := make(map[string]int)
	for i := 0; i < len(in); i += blockSize {
		curBlock := string(in[i : i+blockSize])
		firstSeen, ok := seen[curBlock]
		if ok {
			return true, firstSeen
		}
		seen[curBlock] = i
	}

	return false, -1
}
