package cryptopals

import (
	"bytes"
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
