package cryptopals

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"
)

func TestProblem25(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	ecbct := base64Decode(string(readFile("testdata/25.txt")))
	pt, _ := pkcs7Unpad(ecbDecrypt(ecbct, makeAES(key)))
	ctrKey := randKey(16)
	nonce := new(big.Int).SetBytes(randKey(2)).Uint64()
	ctr := uint64(0)
	ciph := makeAES(ctrKey)
	ctrct := ctrEncrypt(pt, nonce, ctr, ciph)
	edit := makeEditCTR(ctrKey, nonce, ctr)
	msg := []byte("NO PUEDE SER NOOO")
	ctrCopy := make([]byte, len(ctrct))
	copy(ctrCopy, ctrct)
	newct := edit(ctrCopy, 0, msg)

	if len(newct) != len(ctrct) {
		t.Log("ct length changed when it shouldn't")
	}
	decr := ctrDecrypt(newct[:len(msg)], nonce, ctr, ciph)
	if !bytes.Equal(msg, decr) {
		t.Logf("Wrong edition: %s", decr)
	}
	result := recoverCTRPlaintext(ctrct, edit)
	if !bytes.Equal(result, pt) {
		t.Errorf("Random Access CTR recovery error")
	}
	t.Logf("Plaintext recovered:\n%s", string(result))
}

func TestProblem26(t *testing.T) {
	mydata := "AAAAAAAAAAAAAA"
	desire := "x;admin=true;x"
	encrypt, isAdmin := makeCTREncryptorChecker()
	ct1 := encrypt("A")
	ct2 := encrypt("B")
	var boundary int
	for i := 0; i < len(ct1); i++ {
		if ct1[i] != ct2[i] {
			boundary = i
			break
		}
	}
	ptmask := xor([]byte(desire), []byte(mydata))
	cookie := encrypt(mydata)
	data := xor(cookie[boundary:], ptmask)
	copy(cookie[boundary:], data)
	if !isAdmin(cookie) {
		t.Log("CTR cookie rewrite failed")
	}
}

func TestProblem27(t *testing.T) {
	enc, dec := makeCBCiVkeyEncryptorChecker()
	ct := enc("aldocassola@gmail.com")
	k := recoverCBCiVKey(enc, dec)
	if k == nil {
		t.Error("Could not find key")
	}
	pt, _ := pkcs7Unpad(cbcDecrypt(ct, k, makeAES(k)))
	t.Logf("Decrypted data:\n%s", pt)
}

func TestProblem28(t *testing.T) {
	keyedSha1, checkKeyedSha1 := makeSha1HasherVerifier()
	kh2, _ := makeSha1HasherVerifier()
	msg := []byte("Cooking MC's like a pound of bacon")
	sum := keyedSha1(msg)
	msg2 := []byte("Cooking MC's like a pound of bacom")
	if checkKeyedSha1(msg2, sum) != false {
		t.Error("key hash succeded for wrong message")
	}
	sum2 := kh2(msg)
	if checkKeyedSha1(msg, sum2) != false {
		t.Error("key hash succeded for wrong key")
	}
}

func TestProblem29(t *testing.T) {
	sha1hash, sha1check := makeSha1HasherVerifier()
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mysuffix := []byte(";admin=true")
	horig := sha1hash(msg)

	var forged, newH []byte
	success := false
	for i := 0; i < 10000; i++ {
		forged, newH = lengthExtensionKeyedSha1(i, horig, msg, mysuffix)
		if sha1check(forged, newH) {
			t.Logf("Succeded with key length = %d", i)
			success = true
			break
		}
	}
	if !success {
		t.Error("Length extension failed")
	}
}

func TestProblem30(t *testing.T) {
	md4hasher, md4verifier := makeMd4HasherVerifier()
	msg := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	mysuffix := []byte(";admin=true")
	horig := md4hasher(msg)

	var forged, newH []byte
	success := false
	for i := 0; i < 10000; i++ {
		forged, newH = lengthExtensionKeyedMd4(i, horig, msg, mysuffix)
		if md4verifier(forged, newH) {
			t.Logf("Succeded with key length = %d", i)
			success = true
			break
		}
	}
	if !success {
		t.Error("Length extension failed")
	}
}

func TestProblem31(t *testing.T) {
	querySigServer := func(filename, sig string) (resp *http.Response, err error) {
		urlbase := "http://localhost:9000/test?file="
		return http.DefaultClient.Get(urlbase + filename + "&signature=" + sig)
	}
	k := []byte("YELLOW SUBMARINE")
	msg := []byte("Cooking MC's like a pound of bacon")
	myhmac := hmacSha1(k, msg)
	gohmac := hmac.New(sha1.New, k)
	gohmac.Write(msg)
	if !insecureCompare(gohmac.Sum(nil), myhmac, 50*time.Millisecond) {
		t.Error("Wrong HMAC computation")
	}

	delay := 5 * time.Millisecond
	runHTTPHmacFileServer := makeHTTPHmacFileServer(9000, delay)
	go runHTTPHmacFileServer()
	time.Sleep(1 * time.Second)
	filename := "set1.go"

	randSig := hexEncode(randKey(20))
	resp, err := querySigServer(filename, randSig)
	if err != nil {
		t.Error(err.Error())
	}
	defer resp.Body.Close()
	body := make([]byte, int(resp.ContentLength))
	resp.Body.Read(body)
	if resp.StatusCode == 200 {
		t.Error("Valid signature on random sig")
	} else if resp.StatusCode != 500 {
		t.Errorf("Bad response: %s", resp.Status)
	}

	var maxLen = int(sha1.Size)
	if testing.Short() {
		maxLen = 10
	}

	data := readFile(filename)
	truemac := hmacSha1(k, data)
	fmt.Printf("True: % x\n", truemac)
	mac := findHmacSha1Timing(filename, "http://localhost:9000/test", delay, maxLen)
	resp, _ = querySigServer(filename, hexEncode(mac))
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Log("Invalid signature derived")

		if bytes.Count(xor(truemac[:maxLen], mac[:maxLen]), []byte{byte(0)}) < maxLen { //4 byte tolerance
			t.Error()
		} else {
			t.Log(" but close enough\n")
		}
		t.Logf("\nig:\ntrue: %v\nseen: %v\n", truemac, mac)
	}
}

func TestProblem32(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	urlbase := "http://localhost:9001/test?file="
	querySigServer := func(filename, sig string) (resp *http.Response, err error) {

		return http.DefaultClient.Get(urlbase + filename + "&signature=" + sig)
	}

	k := []byte("YELLOW SUBMARINE")
	filename := "set1.go"
	data := readFile(filename)
	truemac := hmacSha1(k, data)
	fmt.Printf("True: % x\n", truemac)

	delay := 5 * time.Millisecond
	runHTTPHmacFileServer := makeHTTPHmacFileServer(9001, delay)
	go runHTTPHmacFileServer()
	time.Sleep(1 * time.Second)
	mac := findHmacSha1TimingAverage(filename, "http://localhost:9001/test", delay)
	resp, err := querySigServer(filename, hexEncode(mac))
	if err != nil {
		t.Error("invalid hmac derived")
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Log("Invalid signature derived")

		if bytes.Count(xor(truemac, mac), []byte{byte(0)}) < 16 { //4 byte tolerance
			t.Error()
		} else {
			t.Log(" but close enough\n")
		}
		t.Logf("\nig:\ntrue: %v\nseen: %v\n", truemac, mac)
	}
}
