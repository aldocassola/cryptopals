package cryptopals

import (
	"bytes"
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

func readFile(filename string) string {
	data, _ := ioutil.ReadFile(filename)
	return string(data)
}

var englishMap = makeLangMap(readFile("testdata/warandpeace.txt"))

func TestProblem3(t *testing.T) {
	ctbytes := hexDecode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	key, pt, _ := findSingleKeyXor(ctbytes, englishMap)
	log.Println("Found plaintext: ", pt)
	log.Println("Key: ", key)
}

func TestProblem4(t *testing.T) {
	data := readFile("testdata/4.txt")
	lines := strings.Split(data, "\n")

	highest := float64(0)
	pt := ""
	linenum := int(0)
	for i, ln := range lines {
		_, testpt, testscore := findSingleKeyXor(hexDecode(ln), englishMap)

		if testscore > highest {
			pt = testpt
			highest = testscore
			linenum = i
		}
	}

	log.Printf("Detected single xor line: %d", linenum)
	log.Printf("plaintext: %s", pt)
}
