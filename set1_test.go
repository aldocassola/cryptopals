package cryptopals

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"io/ioutil"
	"log"
	"strings"
	"testing"
)

func TestProblem1(t *testing.T) {
	hs := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	result := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if hexToBase64(hs) != result {
		t.Error("Wrong hex to base64 transformation:", result)
	}
}

func TestProblem2(t *testing.T) {
	s1 := hexDecode("1c0111001f010100061a024b53535009181c")
	s2 := hexDecode("686974207468652062756c6c277320657965")
	res := xor(s1, s2)
	expected := hexDecode("746865206b696420646f6e277420706c6179")

	if !bytes.Equal(res, expected) {
		t.Error("wrong xor: ", res, expected)
	}
}

func readFile(filename string) []byte {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic("readFile: " + err.Error())
	}
	return data
}

var englishMap = makeLangMap(string(readFile("testdata/warandpeace.txt")))

func TestProblem3(t *testing.T) {
	ctbytes := hexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	key, pt, _ := findSingleKeyXor(ctbytes, englishMap)
	log.Printf("Found plaintext: %s\n", pt)
	log.Printf("Key: %c\n", key)
}

func TestProblem4(t *testing.T) {
	data := readFile("testdata/4.txt")
	lines := strings.Split(string(data), "\n")

	linenum, pt := detectSingleKeyXor(lines, englishMap)
	log.Printf("Detected single xor line: %d", linenum)
	log.Printf("plaintext: %s", pt)

}

func TestProblem5(t *testing.T) {
	plaintext := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	result := repeatingXor([]byte(plaintext), []byte(key))
	expected := hexDecode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

	if !bytes.Equal(result, expected) {
		t.Error("Wrong repeatingXor, result: ", result, "\nexpected: ", expected)
	}
}

func TestProblem6(t *testing.T) {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	expected := 37
	result := hammingDistance([]byte(s1), []byte(s2))

	if expected != result {
		t.Error("wrong hamming distance: ", result)
	}

	data := base64Decode(string(readFile("testdata/6.txt")))
	//data := base64Decode(readFile("testdata/warandpeace.txt.xor"))
	key, pt := findRepeatedKeyXor(data, englishMap)
	log.Printf("Found\nkey: %s (len %d)\nPlaintext:\n%s\n", key, len(key), pt)

}

func TestProblem7(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	data := base64Decode(string(readFile("testdata/7.txt")))
	ciph := makeAES(key)
	pt := ecbDecrypt(data, ciph)
	log.Printf("Data:\n%s", string(pt))
}

func TestProblem8(t *testing.T) {
	data := string(readFile("testdata/8.txt"))
	lines := strings.Fields(string(data))

	for i := range lines {
		if ok, rep := detectECB(hexDecode(lines[i]), aes.BlockSize); ok {
			log.Printf("Detected ECB, line %d: %s\n", i+1, lines[i])
			log.Printf("Repeating block: %s", hex.EncodeToString(rep))
		}
	}
}
