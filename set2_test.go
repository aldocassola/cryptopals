package cryptopals

import (
	"bytes"
	"crypto/aes"
	"log"
	"testing"
)

func TestProblem9(t *testing.T) {
	data := pkcs7Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(data) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Error("wrong pkcs7pad")
	}
	log.Printf("data: %q", data)

	data = pkcs7Pad([]byte("YELLOW SUBMARINE"), 16)
	if string(data) != "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10" {
		t.Error("wrong pkcs7pad")
	}
	log.Printf("data: %q", data)
}

func TestProblem10(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")
	key := bytes.Repeat([]byte{byte(65)}, 16)
	ciph, err := aes.NewCipher(key)
	if err != nil {
		t.Errorf("creating cipher: %s", err.Error())
	}
	if !bytes.Equal(data, ecbDecrypt(ecbEncrypt(data, ciph), ciph)) {
		t.Errorf("Bad ECB encrypt/decrypt")
	}

	data = bytes.Repeat(data, 2)
	iv := bytes.Repeat([]byte{0}, 16)
	if !bytes.Equal(data, cbcDecrypt(cbcEncrypt(data, iv, ciph), iv, ciph)) {
		t.Errorf("Bad CBC encrypt/decrypt")
	}

}
