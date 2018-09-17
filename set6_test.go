package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"net"
	"testing"
	"time"
)

func TestProblem41(t *testing.T) {
	serverPair, err := genRSAKeyPair(2048)
	if err != nil {
		t.Fatal("key generation failed")
	}

	theSecret := &secretData{time.Now().UnixNano(), []byte("there is no spoon")}
	t.Logf("secret data: %s", theSecret.Message)
	secretBytes, err := encodeData(theSecret)
	if err != nil {
		t.Fatal(err.Error())
	}

	ct, err := rsaEncrypt(serverPair.Public, secretBytes)
	if err != nil {
		t.Fatal("rsaEncryption failed")
	}

	go udpServer(10000, makeRSADecryptServer(serverPair.Private, 1*time.Hour))

	decryptResult := make(chan []byte)
	decryptClient := makeRsaDecryptClient(t, allowed, decryptResult)
	clientFunc := func(conn *net.UDPConn) {
		decryptClient(conn, ct)
	}
	go udpClient("localhost", 10000, clientFunc)
	ptBytes, ok := <-decryptResult
	if !ok {
		t.Fatal("rsa decrypt client returned prematurely")
	}

	pt := &secretData{}
	err = decodeData(ptBytes, pt)
	if err != nil {
		t.Fatal(err.Error())
	}

	if pt.Timestamp != theSecret.Timestamp ||
		!bytes.Equal(pt.Message, theSecret.Message) {
		t.Fatal("invalid decryption")
	}

	t.Log("decrypted data:", string(pt.Message))

	//try decrypting again
	decryptResult = make(chan []byte)
	decryptClient = makeRsaDecryptClient(t, denied, decryptResult)
	go udpClient("localhost", 10000, clientFunc)
	ptBytes, ok = <-decryptResult
	if !ok {
		t.Fatal("rsa decrypt client returned prematurely")
	}

	if len(ptBytes) != 0 {
		t.Fatal("Server decrypted same message twice")
	}

	t.Log("second decryption: *DENIED*")

	oracle := makeUnpaddedRSADecryptOracle("localhost", 10000, serverPair.Public, t, allowed)
	ptBytes2 := oracle(ct)
	pt2 := &secretData{}
	err = decodeData(ptBytes2, pt2)
	if err != nil {
		t.Fatal(err.Error())
	}

	if pt2.Timestamp != theSecret.Timestamp ||
		!bytes.Equal(pt2.Message, theSecret.Message) {
		t.Fatal("oracle failed to decrypt blinded data")
	}
	t.Log("Second decryption (unblinded): ", string(pt2.Message))
}

func TestProblem42(t *testing.T) {
	keyPair, err := genRSAKeyPair(1024)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("no lo trates, no/no me trates de engañar")
	sig, err := rsaSign(keyPair.Private, msg, sha256.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signature(%s): % 2x", msg, sig)

	ok, err := rsaVerify(keyPair.Public, msg, sig, sha256.New())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("failed signature verification")
	}

	toForge := []byte("hi mom")
	realSig, err := rsaSign(keyPair.Private, toForge, sha1.New())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signature(%s): % 2x", toForge, realSig)
	ok, _ = rsaVerify(keyPair.Public, toForge, realSig, sha1.New())
	if !ok {
		t.Fatal("real signature failed!")
	}

	forged, err := rsaPKCS15SignatureForge(toForge, sha1.New(), keyPair.Public)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Forged(%s): % 2x", toForge, forged)
	ok, err = rsaVerify(keyPair.Public, toForge, forged, sha1.New())
	if !ok {
		t.Fatal("forged signature failed")
	}
}

func TestProblem43(t *testing.T) {
	givenP := `800000000000000089e1855218a0e7dac38136ffafa72eda7
	859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
	2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
	ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
	b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
	1a584471bb1`
	givenQ := `f4f47f05794b256174bba6e9b396a7707e563c5b`
	givenG := `5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
	458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
	322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
	0f5b64c36b625a097f1651fe775323556fe00b3608c887892
	878480e99041be601a62166ca6894bdd41a7054ec89f756ba
	9fc95302291`

	palsParams := &dsaParams{
		g: newBigIntFromBytes(hexDecode(givenG)),
		p: newBigIntFromBytes(hexDecode(givenP)),
		q: newBigIntFromBytes(hexDecode(givenQ)),
		h: sha1.New,
	}

	palsKeyPair, err := genDSAKeyPair(palsParams)
	if err != nil {
		t.Fatal(err)
	}

	L, N := 1024, 160
	dp, err := newDSAParams(L, N, sha1.New)
	if err != nil {
		t.Fatal(err)
	}

	keyPair, err := genDSAKeyPair(dp)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("tiene los ojos negros, como la noche oscura")
	sig, err := dsaSign(keyPair.private, msg)
	if err != nil {
		t.Fatal(err)
	}
	palSig, err := dsaSign(palsKeyPair.private, msg)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(" Sig: r=%x", sig.r)
	t.Logf("      s=%x", sig.s)
	t.Logf("PSig: r=%x", palSig.r)
	t.Logf("      s=%x", palSig.s)

	ok, err := dsaVerify(keyPair.public, msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("could not verify signature")
	}

	pok, err := dsaVerify(palsKeyPair.public, msg, palSig)
	if err != nil {
		t.Fatal(err)
	}
	if !pok {
		t.Fatal("could not verify pal signature")
	}

}
