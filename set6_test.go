package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"log"
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
	decryptClient := makeRSADecryptClient(t, allowed, decryptResult)
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
	decryptClient = makeRSADecryptClient(t, denied, decryptResult)
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
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("forged signature failed")
	}
}

func Test_newDSAParams(t *testing.T) {
	keyLens := []int{512, 768, 1024, 2048, 3072, 4096}
	hashes := []func() hash.Hash{sha1.New, sha256.New, sha512.New}
	msgs := []string{}

	for _, keyLen := range keyLens {
		for _, h := range hashes {
			t.Log("keyLen:", keyLen)
			t.Log("hashlen:", h().Size())
			params, err := newDSAParams(keyLen, h().Size(), h)
			if err != nil {
				t.Fatal(err)
			}

			dsaPair, err := genDSAKeyPair(params)
			if err != nil {
				log.Fatal(err)
			}

			for _, msg := range msgs {
				t.Log("msg:", msg)
				sig, err := dsaSign(dsaPair.private, []byte(msg))
				if err != nil {
					log.Fatal(err)
				}

				t.Logf("sig: %q", sig)

				if !dsaVerify(dsaPair.public, []byte(msg), sig) {
					log.Fatal("sign verification fail")
				}
			}

		}
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

func TestProblem45(t *testing.T) {
	params := defaultDSAParams()
	badParamsG0 := getBadDSAParams(defaultDSAParams, big.NewInt(0))
	keyPair, err := genDSAKeyPair(params)
	if err != nil {
		t.Fatal(err)
	}
	keyPair.private.params = badParamsG0
	keyPair.public.params = badParamsG0
	msg := "a veces en mi cuarto estando solo, quisiera acabar con todo"
	sig, err := dsaSign(keyPair.private, []byte(msg))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Bad Param Signature:\nr=%2x\ns=%x", sig.r, sig.s)

	if !dsaVerify(keyPair.public, []byte(msg), sig) {
		t.Error("signature for same message failed")
	}

	msg2 := "María Elisa hazme el favor, deja demostrarte mi amor"
	if !dsaVerify(keyPair.public, []byte(msg2), sig) {
		t.Error("signature for other message failed")
	}

	keyPair2, err := genDSAKeyPair(params)
	if err != nil {
		t.Fatal(err)
	}
	badParamsGP1 := getBadDSAParams(defaultDSAParams, new(big.Int).Add(params.p, big.NewInt(1)))
	keyPair2.private.params = badParamsGP1
	keyPair2.public.params = badParamsGP1

	msgHello := "Hello, world"
	msgBye := "Goodbye, world"
	magicSig := makeDSAMagicSigOracle(keyPair2.public)([]byte(msgHello))
	t.Logf("Magic Sig:\nr=%x\ns=%x", magicSig.r, magicSig.s)
	if !dsaVerify(keyPair2.public, []byte(msgHello), magicSig) {
		t.Fatal("magic signature does not verify original string")
	}
	t.Logf("magic signature verifies message: %s", msgHello)

	if !dsaVerify(keyPair2.public, []byte(msgBye), magicSig) {
		t.Fatalf("magic sig is not working for string: %s", msgBye)
	}
	t.Logf("magic signature verifies message: %s", msgBye)
}

func TestProblem46(t *testing.T) {
	keyPair, err := genRSAKeyPair(1024)
	if err != nil {
		t.Fatal(err)
	}

	parOracle := makeRSAParityOracle(keyPair.Private)
	ptx := big.NewInt(1000000)
	ct, err := rsaEncrypt(keyPair.Public, ptx.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if parOracle(ct) == false {
		t.Fatal("oracle gives wrong even parity")
	}

	ptx = big.NewInt(10000001)
	ct, err = rsaEncrypt(keyPair.Public, ptx.Bytes())
	if err != nil {
		t.Fatal(err)
	}

	if parOracle(ct) == true {
		t.Fatal("oracle gives wrong odd parity")
	}

	pt := base64Decode(`
VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGF
yb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==`)
	ct, err = rsaEncrypt(keyPair.Public, pt)
	if err != nil {
		t.Fatal(err)
	}

	decr := decryptWithRSAParityOracle(keyPair.Public, ct, parOracle)

	if string(pt) != string(decr) {
		t.Error("plaintexts differ")
	}
	t.Logf("decrypted: %q", string(decr))
	t.Logf("original : %q", string(pt))
}

func TestProblem47(t *testing.T) {
	pub, isConf, enc := newPKCS1v15Oracle(256)
	m := "kick it, CC"
	c := enc([]byte(m))

	if !isConf(c) {
		t.Fatal("bad isConforming oracle")
	}

	m2, err := unpadPKCS1v15(bb98Full(c, pub, isConf))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("message: %s\nfound: %s", m, m2)
	if string(m2) != m {
		t.Fatal("messages mismatch")
	}
}

func TestProblem48(t *testing.T) {
	pub, isOk, enc := newPKCS1v15Oracle(768)
	m := "kick it, CC"
	c := enc([]byte(m))

	m2, err := unpadPKCS1v15(bb98Full(c, pub, isOk))
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("message: %s\nfound: %s", m, m2)
	if string(m2) != m {
		t.Fatal("messages mismatch")
	}

}
