package cryptopals

import (
	"bytes"
	"math"
	"strings"
	"testing"
	"time"
)

func TestProblem17(t *testing.T) {
	for i := 0; i < 20; i++ {
		encr, padOrcl := makeCBCPaddingOracle()
		ct, iv := encr()
		result, _ := pkcs7Unpad(decryptWithCBCPaddingOracle(ct, iv, padOrcl))
		t.Logf("%s", base64Decode(string(result)))
	}
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

func TestProblem21(t *testing.T) {
	mt := new(MT19937w32)
	mt.Init(uint32(19650218))
	for index := 1; index <= 10; index++ {
		t.Logf("%12d ", mt.Extract())
	}

}

func TestProblem22(t *testing.T) {
	t.Skip()
	start := time.Now().Unix()
	result := runMT19937WithDelay()
	stop := time.Now().Unix()
	seed := getMT19937Seed(result, start, stop)
	mt := new(MT19937w32)
	mt.Init(seed)
	if mt.Extract() != result {
		t.Errorf("Seed doesn't generate seen result")
	}
}

func TestProblem23(t *testing.T) {
	mt := new(MT19937w32)
	mt.Init(uint32(1000))
	clonedmt := new(MT19937w32)
	clonedmt.index = 624
	clonedmt.state = make([]uint32, clonedmt.n())
	for i := range clonedmt.state {
		clonedmt.state[i] = untemper(mt.Extract())
	}

	for i := 0; i < 1000; i++ {
		if mt.Extract() != clonedmt.Extract() {
			t.Error("cloned MT19937 not equal to source")
		}
	}

}

func TestTimer(t *testing.T) {
	now := time.Now()
	time.Sleep(20 * time.Microsecond)
	elapsed := time.Now().Sub(now).Nanoseconds()
	t.Logf("Elapsed: %.3fus", float64(elapsed)/1000.0)
}

func TestProblem24(t *testing.T) {
	seed := uint16(time.Now().UnixNano())
	msg := []byte("YELLOW SUBMARINES") //17 bytes
	mt := new(MT19937w32)
	mt.Init(uint32(seed))
	ct := mtEncrypt(msg, mt)
	mt.Init(uint32(seed))
	res := mtDecrypt(ct, mt)
	if !bytes.Equal(msg, res) {
		t.Error("MT decryption failed")
	}

	enc := getMT19937EncryptPrefixOracle()
	msg = []byte("AAAAAAAAAAAAAA")
	ct = enc(msg)
	s := getMT19937SeedFromCT(msg, ct)
	if s == -1 {
		t.Error("Could not find seed")
	}
	seed = uint16(s)
	mt.Init(uint32(seed))
	pt := mtEncrypt(ct, mt)
	if !bytes.Equal(pt[len(ct)-len(msg):], msg) {
		t.Error("MT decryption does not match known plaintext")
	}

	t.Logf("Password token: %s", getMT19937ResetPwdToken(20))
	start := time.Now().Unix()
	tok := getMT19937ResetPwdToken(20)
	stop := time.Now().Unix()
	if !isMT19937Token(tok, start, stop) {
		t.Error("Could not detect MT19937 output in token")
	}

	start = time.Now().Unix()
	randbytes := randKey(20)
	stop = time.Now().Unix()

	if isMT19937Token(base64Encode(randbytes), start, stop) {
		t.Error("Saw MT19937 output in cprng")
	}
}
