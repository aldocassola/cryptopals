package cryptopals

import (
	"bytes"
	"crypto/aes"
	"strings"
	"testing"
)

func TestProblem9(t *testing.T) {
	data := pkcs7Pad([]byte("YELLOW SUBMARINE"), 20)
	if string(data) != "YELLOW SUBMARINE\x04\x04\x04\x04" {
		t.Error("wrong pkcs7pad")
	}
	t.Logf("data: %q", data)

	data = pkcs7Pad([]byte("YELLOW SUBMARINE"), 16)
	if string(data) != "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10" {
		t.Error("wrong pkcs7pad")
	}
	t.Logf("data: %q", data)
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

	t.Logf("Observed freqs: %v", freqs)

}

func TestProblem12(t *testing.T) {
	var mistery = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	oracle := makePayloadEncryptionOracle(mistery, makeAES(randBytes(aes.BlockSize)))
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
	t.Logf("Found plaintext:\n%s", pt)
}

func TestProblem13(t *testing.T) {
	obj := kvParse("foo=bar&baz=qux&zap=zazzle")
	t.Logf("%s", obj)
	result := profileFor("foo@bar.com&role=admin")
	t.Logf("%s", result)
	if kvParse(result).Get("role") == "admin" {
		t.Error("Too easy to break")
	}

	encryptProfile, decryptProfile := makeProfileCiphers()
	admct := makeAdminProfile(encryptProfile)
	admprof := decryptProfile(admct)
	if kvParse(admprof).Get("role") != "admin" {
		t.Error("Could not make admin profile")
	}
	t.Logf("Got profile: %s", admprof)
}

func TestProblem14(t *testing.T) {
	var mistery = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK`
	rhoracle := makeRandomHeadPayloadEncryptionOracle(mistery, makeAES(randBytes(aes.BlockSize)))
	foracle := fixRandHeaderOracle(rhoracle)
	pt := ecbDecrypt1by1(foracle)

	if pt == nil {
		t.Error("Could not find plaintex")
	}
	t.Logf("Found plaintext:\n%s", pt)
}

func TestProblem15(t *testing.T) {
	expected := "ICE ICE BABY"
	t1 := "ICE ICE BABY\x04\x04\x04\x04"
	res, err := pkcs7Unpad([]byte(t1))
	if err != nil || strings.Compare(string(res), expected) != 0 {
		t.Error("Bad padding check1")
	}
	t2 := "ICE ICE BABY\x05\x05\x05\x05"
	res, err = pkcs7Unpad([]byte(t2))
	if err == nil || strings.Compare(string(res), expected) == 0 {
		t.Error("Bad padding check2")
	}
	t3 := "ICE ICE BABY\x01\x02\x03\x04"
	res, err = pkcs7Unpad([]byte(t3))
	if err == nil || strings.Compare(string(res), expected) == 0 {
		t.Error("Bad padding check3")
	}
}

func TestProblem16(t *testing.T) {
	encryptor, decryptCheck := makeCBCEncryptorChecker()
	mytext := "xXXXXXXXXXXX"
	desire := "x;admin=true"
	ct := encryptor(desire)
	if decryptCheck(ct) {
		t.Error("admin inserted to ciphertext")
	}

	bs := aes.BlockSize
	xormask := xor([]byte(mytext), []byte(desire))
	ct = encryptor(mytext)
	newBlock := xor(ct[bs:bs+len(xormask)], xormask)
	copy(ct[bs:bs+len(xormask)], newBlock)
	if decryptCheck(ct) == false {
		t.Error("Could not rewrite string")
	}
}
