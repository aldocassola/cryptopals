package cryptopals

import (
	"bytes"
	"crypto/sha256"
	mathrand "math/rand"
	"strings"
	"testing"
	"time"
)

func toByteSlice(in uint64) []byte {
	result := make([]byte, 8)
	for i := uint(0); i < 7; i++ {
		result[i] = byte(in >> (56 - 8*i))
	}
	return result
}

const nistPstrs = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
	e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
	3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
	6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
	24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
	c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
	bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
	fffffffffffff`

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
	var nistPstr string
	for _, v := range strings.Fields(nistPstrs) {
		nistPstr += v
	}
	nistP := bytesToBigInt(hexDecode(nistPstr))
	nistG := bytesToBigInt(hexDecode("02"))
	biga := bytesToBigIntMod(nistP)
	bigb := bytesToBigIntMod(nistP)
	bigA := bigPowMod(nistG, biga, nistP)
	bigB := bigPowMod(nistG, bigb, nistP)
	bigS1 := bigPowMod(bigA, bigb, nistP)
	bigS2 := bigPowMod(bigB, biga, nistP)
	if bigS1.Cmp(bigS2) != 0 {
		t.Error("big powmod DH differs")
	}
}

func TestProblem34(t *testing.T) {
	var nistPstr string
	for _, v := range strings.Fields(nistPstrs) {
		nistPstr += v
	}
	nistP := bytesToBigInt(hexDecode(nistPstr))
	nistG := bytesToBigInt(hexDecode("02"))
	params, apriv := genParams(nistG, nistP)
	bpriv := makeDHprivate(nistP)
	bpub := makeDHpublic(params, bpriv)
	akey := dhKeyExchange(params, bpub, apriv)
	bkey := dhKeyExchange(params, params.pubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH secrets differ")
	}

	go runDHEchoServer(9001)
	time.Sleep(3 * time.Second)
	dhEchoTestClient("localhost", 9001, nistG, nistP, 10, t)
}
