package cryptopals

import "testing"

func TestProblem17(t *testing.T) {
	encr, padOrcl := makeCBCPaddingOracle()
	ct, iv := encr()
	result, _ := pkcs7Unpad(decryptWithCBCPaddingOracle(ct, iv, padOrcl))
	t.Logf("%s", base64Decode(string(result)))

}

func TestProblem18(t *testing.T) {
	ct := base64Decode(`L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==`)
	nonce := uint64(0)
	ctrStart := uint64(0)
	ciph := makeAES([]byte("YELLOW SUBMARINE"))
	pt := ctrDecrypt(ct, nonce, ctrStart, ciph)
	t.Logf("Plaintext: %s", pt)
	if len(pt) != len(ct) {
		t.Error("Mismatched plaintext/ciphertext lengths")
	}
}
