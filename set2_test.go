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

func TestProblem11(t *testing.T) {
	//rand.Seed(38)
	blackBox := makeEncryptionOracle(aes.BlockSize)
	detectionOracle := makeCBCDetectOracle(aes.BlockSize)
	freqs := [2]uint32{0, 0}

	for i := 0; i < 1000; i++ {
		if detectionOracle(blackBox) {
			freqs[0]++
		} else {
			freqs[1]++
		}
	}

	log.Printf("Observed freqs: %v", freqs)

}

func TestProblem12(t *testing.T) {
	var mistery = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	oracle := makePayloadEncryptionOracle(mistery, makeAES(randKey(aes.BlockSize)))
	data := bytes.Repeat([]byte{'A'}, aes.BlockSize*2)
	ct := oracle(data)
	tt, _ := detectECB(ct, aes.BlockSize)
	if !tt {
		t.Error("did not detect ECB correctly")
	}

	pt := ecbDecrypt1by1(oracle)
	if pt == nil {
		t.Error("Could not find plaintex")
	}
	log.Printf("Found plaintext:\n%s", pt)
}

func TestProblem13(t *testing.T) {
	result := kvParse("foo=bar&baz=qux&zap=zazzle")
	expected := `{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}`
	if result != expected {
		t.Error("wrong parsing")
	}

	myprofiles := []profile{
		profile{
			email: "aldo@bar.com",
			uid:   100,
			role:  "user",
		},
		profile{
			email: "god@bar.com",
			uid:   0,
			role:  "admin",
		},
		profile{
			email: "foo@bar.com",
			uid:   10,
			role:  "user",
		},
	}

	profileFor := makeProfiles(myprofiles)
	expected = "email=foo@bar.com&uid=10&role=user"
	result = profileFor("foo@bar.com")
	if expected != result {
		t.Error("Wrong encoding: " + result)
	}

	encryptProfile, decryptProfile := makeProfileCiphers(myprofiles)
	rootblocks := encryptProfile("god@bar.com")
	rootlast := rootblocks[len(rootblocks)-2*aes.BlockSize:]
	userblocks := encryptProfile("foo@bar.com")
	userblocks = append(userblocks[:len(userblocks)-2*aes.BlockSize], rootlast...)
	newprof := decryptProfile(userblocks)
	log.Printf("modified profile:\n%s", newprof)

}

func TestProblem14(t *testing.T) {
	var mistery = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	rhoracle := makeRandomHeadPayloadEncryptionOracle(mistery, makeAES(randKey(aes.BlockSize)))
	foracle := fixRandHeaderOracle(rhoracle)
	pt := ecbDecrypt1by1(foracle)

	if pt == nil {
		t.Error("Could not find plaintex")
	}
	log.Printf("Found plaintext:\n%s", pt)
}
