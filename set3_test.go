package cryptopals

import "testing"
import "strings"
import "math"

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

func TestProblem19(t *testing.T) {
	var data = `SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
	Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
	RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
	RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
	SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
	T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
	T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
	UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
	QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
	T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
	VG8gcGxlYXNlIGEgY29tcGFuaW9u
	QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
	QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
	QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
	QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
	QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
	VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
	SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
	SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
	VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
	V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
	V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
	U2hlIHJvZGUgdG8gaGFycmllcnM/
	VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
	QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
	VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
	V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
	SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
	U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
	U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
	VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
	QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
	SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
	VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
	WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
	SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
	SW4gdGhlIGNhc3VhbCBjb21lZHk7
	SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
	VHJhbnNmb3JtZWQgdXR0ZXJseTo=
	QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=`
	lines := strings.Fields(data)
	var ciphertexts []byte
	enc := makeFixedNonceCTR()

	for _, v := range lines {
		ciphertexts = append(ciphertexts, enc(base64Decode(v))...)
	}

}

func TestProblem20(t *testing.T) {
	lines := strings.Fields(string(readFile("testdata/20.txt")))
	var ciphertexts [][]byte
	var minLen = math.MaxInt32
	enc := makeFixedNonceCTR()
	for i, v := range lines {
		ciphertexts = append(ciphertexts, enc(base64Decode(v)))
		if len(ciphertexts[i]) < minLen {
			minLen = len(ciphertexts[i])
		}
	}

	key, _ := findFixedCTRKeystream(ciphertexts, minLen, enc, englishMap)
	key[0] ^= byte('\x27')
	t.Logf("Key: %v\n", key)
	for i := range ciphertexts {
		t.Logf("Plaintext %d: %s\n", i, xor(key, ciphertexts[i]))
	}

}
