package cryptopals

import (
	"math/big"
	"bytes"
	"crypto/sha256"
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
	nistG := newBigIntBytes(hexDecode("02"))
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
	nistG := newBigIntBytes(hexDecode("02"))
	params, apriv := makeParamsPub(nistG, nistP)
	bpriv := makeDHprivate(nistP)
	bpub := makeDHpublic(params.generator, params.prime, bpriv)
	akey := dhKeyExchange(params.prime, bpub, apriv)
	bkey := dhKeyExchange(params.prime, params.pubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH secrets differ")
	}

	go runDHEchoServer(9001)
	//time.Sleep(1 * time.Second)
	dhEchoTestClient("localhost", 9001, nistG, nistP, 10, t)

	aparams, apriv := makeParamsPub(nistG, nistP)
	bparams, _ := makeParamsPub(nistG, nistP)
	bparams.pubKey = nistP
	bpriv = makeDHprivate(nistP)
	bpub = makeDHpublic(bparams.generator, bparams.prime, bpriv)
	bpubfora := nistP
	akey = dhKeyExchange(aparams.prime, bpubfora, apriv)
	bkey = dhKeyExchange(bparams.prime, bparams.pubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH attacked secrets differ")
	}
	go runParameterInjector("localhost", 9001, 9002)
	dhEchoTestClient("localhost", 9002, nistG, nistP, 10, t)
}

func TestProblem35(t *testing.T) {
	g := newBigIntBytes(hexDecode("02"))
	p := getNistP()
	go runDHNegoEchoServer(9091)
	go runDHNegoParameterInjector("localhost", 9091, 9092, big.NewInt(1))
	dhNegoEchoTestClient("localhost", 9092, g, p, 100, t)
	
}
