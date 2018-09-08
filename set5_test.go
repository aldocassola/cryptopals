package cryptopals

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	mathrand "math/rand"
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

func TestProblem33(t *testing.T) {
	result := hmacH(sha256.New, []byte(""), []byte(""))
	expect := hexDecode("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad")

	if !bytes.Equal(result, expect) {
		t.Fatal("hmac invalid")
	}

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

	nativeS1 := new(big.Int).Exp(bigA, bigb, nistP)
	nativeS2 := new(big.Int).Exp(bigB, biga, nistP)

	if bigS1.Cmp(nativeS1) != 0 ||
		bigS2.Cmp(nativeS2) != 0 {
		t.Error("Invalid PowMod")
	}

}

func TestProblem34(t *testing.T) {
	nistP := getNistP()
	nistG := big.NewInt(2)
	params, apriv := makeParamsPub(nistG, nistP)
	bpriv := makeDHprivate(nistP)
	bpub := makeDHpublic(params.Generator, params.Prime, bpriv)
	akey := dhKeyExchange(sha256.New(), params.Prime, bpub, apriv)
	bkey := dhKeyExchange(sha256.New(), params.Prime, params.PubKey, bpriv)
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
	akey = dhKeyExchange(sha256.New(), aparams.Prime, bpubfora, apriv)
	bkey = dhKeyExchange(sha256.New(), bparams.Prime, bparams.PubKey, bpriv)
	if !bytes.Equal(akey, bkey) {
		t.Error("DH attacked secrets differ")
	}
	go udpServer(9002, makeParameterInjector("localhost", 9001, t))
	udpClient("localhost", 9002, makeDHEchoTestClient(nistG, nistP, msgCount, t))
}

func TestProblem35(t *testing.T) {
	g := big.NewInt(2)
	p := getNistP()
	msgCount := 5

	go udpServer(8991, makeDHNegoEchoServer())
	udpClient("localhost", 8991, makeDHNegoEchoTestClient(g, p, msgCount, t))

	go udpServer(9091, makeDHNegoEchoServer())
	go udpServer(9092, makeDHNegoParameterInjector("localhost", 9091, new(big.Int), t))
	udpClient("localhost", 9092, makeDHNegoEchoTestClient(g, p, msgCount, t))

	go udpServer(9191, makeDHNegoEchoServer())
	go udpServer(9192, makeDHNegoParameterInjector("localhost", 9191, big.NewInt(1), t))
	udpClient("localhost", 9192, makeDHNegoEchoTestClient(g, p, msgCount, t))

	go udpServer(9291, makeDHNegoEchoServer())
	go udpServer(9292, makeDHNegoParameterInjector("localhost", 9291, big.NewInt(-1), t))
	udpClient("localhost", 9292, makeDHNegoEchoTestClient(g, p, msgCount, t))
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

	go udpServer(9203, makeSRPServer(srpin, t))
	for index := 1; index < 2; index++ {
		badInt := new(big.Int).Mul(srpin.params.nistP, big.NewInt(int64(index)))
		udpClient("localhost", 9203, makeSRPClient(id, "bad password", badInt, t, true))
	}
}

func TestProblem38(t *testing.T) {
	id := "aldocassola@gmail.com"
	pass := "(29ssG$J%J56ko"

	srpin := newSRPInput(id, pass)

	go udpServer(9301, makeSimpleSRPServer(srpin, t))
	udpClient("localhost", 9301, makeSimpleSRPClient(id, pass, t, true))

	udpClient("localhost", 9301, makeSimpleSRPClient(id, "bad password", t, false))

	c := make(chan string)
	s := newSRPInput("", "")
	wl := loadWordList("testdata/english_alpha.txt")

	var pass2 string
	if testing.Short() {
		pass2 = wl[mathrand.Intn(300)]
	} else {
		pass2 = wl[mathrand.Intn(len(wl))]
	}

	go udpServer(9302, makeSimpleSRPCracker(&s.params, wl, t, c))
	go udpClient("localhost", 9302, makeSimpleSRPClient(id, pass2, t, false))
	result := <-c
	if result != pass2 {
		t.Error("SRP online key search failed")
	}
}

func TestProblem39(t *testing.T) {
	for index := 0; index < 10; index++ {
		n17 := big.NewInt(17)
		n3120 := big.NewInt(3120)

		gcd, _, _ := extEuclidean(n3120, n17)
		gcd2 := new(big.Int).GCD(nil, nil, n3120, n17)
		if gcd.Cmp(gcd2) != 0 {
			t.Fatal("euclidean invalid")
		}

		inv17, err := invMod(n17, n3120)
		if err != nil {
			t.Fatal("Invalid invmod(17, 3120)")
		}

		if inv17.Cmp(big.NewInt(2753)) != 0 {
			t.Fatal("wrong inverse computed")
		}

		a := newBigIntFromBytes(randKey(16))
		b, err := rand.Prime(rand.Reader, 128)
		if err != nil {
			t.Log("Generating prime:", err.Error())
		}
		a.Mod(a, b)

		mygcd, x, y := extEuclidean(a, b)
		rx, ry := new(big.Int), new(big.Int)
		gcd = new(big.Int).GCD(rx, ry, a, b)

		if mygcd.Cmp(gcd) != 0 {
			t.Fatal("invalid gcd computation")
		}

		if rx.Cmp(x) != 0 || ry.Cmp(y) != 0 {
			t.Fatal("invalid gcd computation coefficients")
		}

		inv := new(big.Int).ModInverse(a, b)
		myinv, err := invMod(a, b)

		if (inv == nil && err == nil) ||
			(inv != nil && err != nil) {
			t.Fatal("Inverse obtained where none exists")
		}

		if inv.Cmp(myinv) != 0 {
			t.Fatal("Invalid inverse")
		}

		keyPair, err := genRSAKeyPair(2048)
		if err != nil {
			t.Fatal("generating RSA keypair", err.Error())
		}
		m := big.NewInt(42)
		c, err := rsaEncrypt(keyPair.Public, m.Bytes())
		if err != nil {
			t.Fatal("encrypting", err.Error())
		}

		m2, err := rsaDecrypt(keyPair.Private, c)
		if err != nil {
			t.Fatal("decrypting", err.Error())
		}

		if newBigIntFromBytes(m2).Cmp(m) != 0 {
			t.Fatal("invalid encryption/decryption")
		}

		m = new(big.Int).SetBytes([]byte("Cooking MC's like a pound of bacon"))
		c, err = rsaEncrypt(keyPair.Public, m.Bytes())
		if err != nil {
			t.Fatal("encrypting2", err.Error())
		}

		m2, err = rsaDecrypt(keyPair.Private, c)
		if err != nil {
			t.Fatal("decrypting2", err.Error())
		}

		if string(m2) != string(m.Bytes()) {
			t.Fatal("invalid encryption/decryption2")
		}
	}
}

func TestProblem40(t *testing.T) {
	three := big.NewInt(3)

	for i := 0; i < 1000; i++ {
		bigi := new(big.Int).Rand(
			mathrand.New(mathrand.NewSource(time.Now().UnixNano())),
			big.NewInt(0).SetBit(big.NewInt(0), 1025, 1))
		bigi3 := new(big.Int).Exp(bigi, three, nil)

		rooti, err := cubeRoot(bigi3)
		if err != nil {
			t.Fatal(err.Error())
		}

		if rooti.Cmp(bigi) != 0 {
			t.Fatalf("result %d is not cuberoot of %d", rooti.Int64(), i)
		}
	}
	fmt.Println()

	msg := "cooking mc's like a pound of bacon"

	kp0, _ := genRSAKeyPair(1024)
	kp1, _ := genRSAKeyPair(1024)
	kp2, _ := genRSAKeyPair(1024)

	c0, _ := rsaEncrypt(kp0.Public, []byte(msg))
	c1, _ := rsaEncrypt(kp1.Public, []byte(msg))
	c2, _ := rsaEncrypt(kp2.Public, []byte(msg))

	mb, err := rsaCubeDecrypt(kp0.Public, kp1.Public, kp2.Public, c0, c1, c2)
	if err != nil {
		t.Fatal("decrypting:", err.Error())
	}
	m0 := string(mb)

	t.Log("msg:", msg)
	t.Log("dec:", m0)
	if m0 != msg {
		t.Fatal("decryption failed")
	}

}
