package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"math/big"
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
	palsParams := defaultDSAParams()
	yStr := `84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
	abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
	e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
	1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
	bb283e6633451e535c45513b2d33c99ea17`
	palY, ok := new(big.Int).SetString(flattenStr(yStr), 16)
	if !ok {
		t.Fatal("failed to load y string")
	}
	pubKey := &dsaPublic{
		y:      palY,
		params: palsParams}

	msg := `For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`
	h := palsParams.h()
	h.Write([]byte(msg))
	hmsg := h.Sum(nil)
	t.Logf("hmsg: %x", hmsg)
	needH := hexDecode("d2d0714f014a9784047eaeccf956520045c45265")
	if !bytes.Equal(hmsg, needH) {
		t.Fatal("hash is wrong")
	}

	rnum, ok := new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	if !ok {
		t.Fatal("r could not be parsed")
	}
	snum, ok := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)
	if !ok {
		t.Fatal("s could not be parsed")
	}
	t.Logf("Sig r=%s", rnum.Text(16))
	t.Logf("    s=%s", snum.Text(16))
	palSig := &dsaSignature{
		r: rnum.Bytes(),
		s: snum.Bytes()}

	targetFP := hexDecode("0954edd5e0afe5542a4adf012611a91912a3ec16")

	priv := loopKDSAPrivate(pubKey, palSig, hmsg, targetFP)
	if priv == nil {
		t.Fatal("failed to find private key")
	}

	trialsig, _ := dsaSign(priv, []byte(msg))
	ok = dsaVerify(pubKey, []byte(msg), trialsig)
	if !ok {
		t.Fatal("found private key is wrong")
	}

	t.Logf("found x: %2x", priv.x.Bytes())
}

func TestProblem44(t *testing.T) {
	msgs := makeDSASignedMessages("testdata/44.txt")
	for _, m := range msgs {
		mh := sha1.Sum([]byte(m.msg))
		mht := new(big.Int).SetBytes(mh[:]).Text(16)
		if m.hmsg != mht {
			t.Errorf("hash does not match message\nh1: %s\nh2: %s", m.hmsg, mht)
		}
	}
	dupes := findRepeatedDSAK(msgs)
	for i, group := range dupes {
		t.Logf("Group %d, r: %s", i, group[0].r)
		for _, m := range group {
			t.Logf(" m: %q", m)
		}
	}

	params := defaultDSAParams()
	targetFP := "ca8f6f7c66fa362d40760d135b763eb8527d3d52"

	for i := 0; i < len(dupes); i++ {
		priv := findDSPrivateFromRepeatedK(dupes[i], params)
		privFP := fmt.Sprintf("%x", sha1.Sum([]byte(priv.x.Text(16))))

		t.Logf("found private key: x=%s", priv.x.Text(16))
		t.Logf("priv FP: %s", privFP)
		t.Logf("targ FP: %s", targetFP)

		if privFP != targetFP {
			t.Error("private key not found")
		}
	}
}
