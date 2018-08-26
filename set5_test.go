package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"math/big"
	mathrand "math/rand"
	"testing"
)

func toByteSlice(in uint64) []byte {
	result := make([]byte, 8)
	for i := uint(0); i < 7; i++ {
		result[i] = byte(in >> (56 - 8*i))
	}
	return result
}

func TestProblem33(t *testing.T) {
	g := uint64(5)
	p := uint64(37)
	a := uint64(mathrand.Intn(37))
	b := uint64(mathrand.Intn(37))
	A := powMod(g, a, p)
	B := powMod(g, b, p)
	s1 := powMod(A, b, p)
	s2 := powMod(B, a, p)
	if s1 != s2 {
		t.Error("Shared DH differs")
	}
	hashfun := sha256.New()
	hashfun.Write(toByteSlice(s1))
	key := hashfun.Sum(nil)
	t.Logf("keys (from s=%d): % x : % x", s1, key[0:16], key[16:])
	nistP := getNistP()
	nistG := big.NewInt(2)
	biga := newRandBigIntMod(nistP)
	bigb := newRandBigIntMod(nistP)
	bigA := bigPowMod(nistG, biga, nistP)
	bigB := bigPowMod(nistG, bigb, nistP)
	bigS1 := bigPowMod(bigA, bigb, nistP)
	bigS2 := bigPowMod(bigB, biga, nistP)
	if bigS1.Cmp(bigS2) != 0 {
		t.Error("big powmod DH differs")
	}
}

func TestProblem34(t *testing.T) {
	nistP := getNistP()
	nistG := big.NewInt(2)
	params, apriv := makeParamsPub(nistG, nistP)
	bpriv := makeDHprivate(nistP)
	bpub := makeDHpublic(params.Generator, params.Prime, bpriv)
	akey := dhKeyExchange(params.Prime, bpub, apriv)
	bkey := dhKeyExchange(params.Prime, params.PubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH secrets differ")
	}

	msgCount := 5
	go udpServer(9001, makeDHEchoServer())
	//time.Sleep(1 * time.Second)
	udpClient("localhost", 9001, makeDHEchoTestClient(nistG, nistP, msgCount, t))

	aparams, apriv := makeParamsPub(nistG, nistP)
	bparams, _ := makeParamsPub(nistG, nistP)
	bparams.PubKey = nistP
	bpriv = makeDHprivate(nistP)
	bpub = makeDHpublic(bparams.Generator, bparams.Prime, bpriv)
	bpubfora := nistP
	akey = dhKeyExchange(aparams.Prime, bpubfora, apriv)
	bkey = dhKeyExchange(bparams.Prime, bparams.PubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH attacked secrets differ")
	}
	go runParameterInjector("localhost", 9001, 9002, t)
	udpClient("localhost", 9002, makeDHEchoTestClient(nistG, nistP, msgCount, t))
}

func TestProblem35(t *testing.T) {
	g := big.NewInt(2)
	p := getNistP()
	msgCount := 5

	go runDHNegoEchoServer(8991)
	dhNegoEchoTestClient("localhost", 8991, g, p, msgCount, t)
	t.Log("Client-server passed")

	go runDHNegoEchoServer(9091)
	go runDHNegoParameterInjector("localhost", 9091, 9092, new(big.Int), t)
	dhNegoEchoTestClient("localhost", 9092, g, p, msgCount, t)

	go runDHNegoEchoServer(9191)
	go runDHNegoParameterInjector("localhost", 9191, 9192, big.NewInt(1), t)
	dhNegoEchoTestClient("localhost", 9192, g, p, msgCount, t)

	go runDHNegoEchoServer(9291)
	go runDHNegoParameterInjector("localhost", 9291, 9292, big.NewInt(-1), t)
	dhNegoEchoTestClient("localhost", 9292, g, p, msgCount, t)
}

func TestProblem36(t *testing.T) {
	//simulate server registration
	id := "aldo@example.com"
	pass := "r9yN69Gs34hg&"
	sRPin := newSRPInput(id, pass)
	rec := new(sRPRecord).Init(sRPin, 16)

	//client initializes
	aPriv := makeDHprivate(sRPin.params.nistP)
	aPub := bigPowMod(sRPin.params.generator, aPriv, sRPin.params.nistP)

	//server
	bpriv := makeDHprivate(sRPin.params.nistP)
	bPub := getSRPServerPub(bpriv, rec, &sRPin.params)

	//sends to client: bPub and:
	salt := base64Decode(rec.salt)
	u := newBigIntFromByteHash(sha1.New(), aPub.Bytes(), bPub.Bytes())

	//each side computes K
	kA := sRPServerDerive(rec, bpriv, aPub, u, sRPin.params.nistP)
	kB := sRPClientDerive(sRPin, salt, aPriv, bPub, u)

	t.Logf("server key: %s", hexEncode(kA))
	t.Logf("client key: %s", hexEncode(kB))

	if subtle.ConstantTimeCompare(kA, kB) != 1 {
		t.Error("SRP client and server keys disagree")
	}
}

func TestProblem37(t *testing.T) {
	id := "aldocassola@gmail.com"
	pass := "(29ssG$J%J56ko"
	srpin := newSRPInput(id, pass)

	go udpServer(9200, makeSRPServer(srpin, t))
	udpClient("localhost", 9200, makeSRPClient(id, pass, nil, t, true))

	go udpServer(9201, makeSRPServer(srpin, t))
	udpClient("localhost", 9201, makeSRPClient(id, "bad password", nil, t, false))

	go udpServer(9202, makeSRPServer(srpin, t))
	udpClient("localhost", 9202, makeSRPClient(id, "bad password", big.NewInt(0), t, true))

	for index := 1; index < 100; index++ {
		go udpServer(9203, makeSRPServer(srpin, t))
		badInt := new(big.Int).Mul(srpin.params.nistP, big.NewInt(int64(index)))
		udpClient("localhost", 9203, makeSRPClient(id, "bad password", badInt, t, true))
	}

}
