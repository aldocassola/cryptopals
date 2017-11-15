package cryptopals

import "testing"
import "encoding/hex"
import "bytes"

func TestProblem1(t *testing.T) {
	hs := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	result := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	if hexToBase64(hs) != result {
		t.Error("Wrong hex to base64 transformation:", result)
	}
}

func TestProblem2(t *testing.T) {
	s1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	s2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	res := xor(s1, s2)
	expected, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")

	if !bytes.Equal(res, expected) {
		t.Error("wrong xor: ", res, expected)
	}
}
