package cryptopals

import (
	"bytes"
	"math/big"
	"testing"
)

func TestProblem25(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	ecbct := base64Decode(string(readFile("testdata/25.txt")))
	pt, _ := pkcs7Unpad(ecbDecrypt(ecbct, makeAES(key)))
	ctrKey := randKey(16)
	nonce := big.NewInt(0).SetBytes(randKey(2)).Uint64()
	ctr := uint64(0)
	ciph := makeAES(ctrKey)
	ctrct := ctrEncrypt(pt, nonce, ctr, ciph)
	edit := makeEditCTR(ctrKey, nonce, ctr)
	msg := []byte("NO PUEDE SER NOOO")
	newct := edit(ctrct, 0, msg)

	if len(newct) != len(ctrct) {
		t.Log("ct length changed when it shouldn't")
	}
	decr := ctrDecrypt(newct[:len(msg)], nonce, ctr, ciph)
	if !bytes.Equal(msg, decr) {
		t.Logf("Wrong edition: %s", decr)
	}
	result := recoverCTRPlaintext(ctrct, edit)
	if !bytes.Equal(result, pt) {
		t.Errorf("Random Access CTR recovery error")
	}
	t.Logf("Plaintext recovered:\n%s", string(result))
}

func TestProblem26(t *testing.T) {
	mydata := "AAAAAAAAAAAAAA"
	desire := "x;admin=true;x"
	encrypt, isAdmin := makeCTREncryptorChecker()
	ct1 := encrypt("A")
	ct2 := encrypt("B")
	var boundary int
	for i := 0; i < len(ct1); i++ {
		if ct1[i] != ct2[i] {
			boundary = i
			break
		}
	}
	ptmask := xor([]byte(desire), []byte(mydata))
	cookie := encrypt(mydata)
	data := xor(cookie[boundary:], ptmask)
	copy(cookie[boundary:], data)
	if !isAdmin(cookie) {
		t.Log("CTR cookie rewrite failed")
	}
}

func TestProblem27(t *testing.T) {
	enc, dec := makeCBCiVkeyEncryptorChecker()
	ct := enc("aldocassola@gmail.com")
	k := recoverCBCiVKey(enc, dec)
	if k == nil {
		t.Error("Could not find key")
	}
	pt, _ := pkcs7Unpad(cbcDecrypt(ct, k, makeAES(k)))
	t.Logf("Decrypted data:\n%s", pt)
}

func TestProblem28(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	msg := []byte("Cooking MC's like a pound of bacon")
	sum := keyedSha1(key, msg)
	msg2 := []byte("Cooking MC's like a pound of bacom")
	if checkKeyedSha1(key, msg2, sum) != false {
		t.Error("key hash succeded for wrong message")
	}
	if checkKeyedSha1(key[:len(key)-1], msg, sum) != false {
		t.Error("key hash succeded for wrong key")
	}
}
