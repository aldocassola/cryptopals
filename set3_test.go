package cryptopals

import "testing"

func TestProblem17(t *testing.T) {

	for i := 0; i < 20; i++ {
		encr, padOrcl := makeCBCPaddingOracle()
		ct, iv := encr()
		result, _ := pkcs7Unpad(decryptWithCBCPaddingOracle(ct, iv, padOrcl))
		t.Logf("%s", base64Decode(string(result)))
	}
}
