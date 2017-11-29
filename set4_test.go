package cryptopals

import "testing"
import "math/big"
import "bytes"

func TestProblem25(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	ecbct := base64Decode(string(readFile("testdata/25.txt")))
	pt := ecbDecrypt(ecbct, makeAES(key))
	t.Logf("Original data:\n%s", pt)
	ctrKey := randKey(16)
	nonce := big.NewInt(0).SetBytes(randKey(2)).Uint64()
	ctr := uint64(0)
	ciph := makeAES(ctrKey)
	ctrct := ctrEncrypt(pt, nonce, ctr, ciph)
	edit := makeEditCTR(nonce, ctr)
	msg := []byte("NO PUEDE SER NOOO")
	newct := edit(ctrct, ctrKey, 0, msg)

	if len(newct) != len(ctrct) {
		t.Log("ct length changed when it shouldn't")
	}
	if !bytes.Equal(msg, ctrDecrypt(newct[:len(msg)], nonce, ctr, ciph)) {
		t.Log("Wrong edition")
	}
	t.Logf("Edited data:\n%s", ctrDecrypt(newct, nonce, ctr, ciph))
}
