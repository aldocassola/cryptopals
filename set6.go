package cryptopals

import (
	"crypto/sha256"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"testing"
	"time"
)

type rsaDecryptRequest struct {
	Ciphertext []byte
}

type decryptStatus int

const (
	allowed decryptStatus = 0
	denied  decryptStatus = -1
)

type rsaDecryptResponse struct {
	Status decryptStatus
	Data   []byte
}

type secretData struct {
	Timestamp int64
	Message   []byte
}

func makeRSADecryptServer(privKey *rsaPrivate, ttl time.Duration) func(
	*net.UDPConn, *net.UDPAddr, []byte) {
	failResponse := rsaDecryptResponse{
		denied,
		[]byte(""),
	}
	seenMsg := make(map[[sha256.Size]byte]interface{})
	h := sha256.New()
	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		req := new(rsaDecryptRequest)
		err := decodeData(buf, req)
		if err != nil {
			sendData(&failResponse, conn, addr)
			return
		}

		var hmsg [sha256.Size]byte
		h.Reset()
		h.Write(req.Ciphertext)
		copy(hmsg[:], h.Sum(nil))

		_, ok := seenMsg[hmsg]
		if ok {
			sendData(&failResponse, conn, addr)
			return
		}
		//it's cool. Decrypt
		ptbytes, err := rsaDecrypt(privKey, req.Ciphertext)
		if err != nil {
			log.Print("rsaDecrypt svr:", err.Error())
			sendData(&failResponse, conn, addr)
		}

		seenMsg[hmsg] = true

		response := &rsaDecryptResponse{
			Status: allowed,
			Data:   ptbytes,
		}
		err = sendData(response, conn, addr)
		if err != nil {
			log.Print("rsDecrypt svr sending data:", err.Error())
		}
	}
}

func makeRsaDecryptClient(
	t *testing.T, expectedStatus decryptStatus,
	result chan []byte) func(*net.UDPConn, []byte) {

	return func(conn *net.UDPConn, ciphertext []byte) {
		defer close(result)
		request := &rsaDecryptRequest{ciphertext}
		err := sendData(request, conn, nil)
		if err != nil {
			t.Error("rsaDecryptClient: failed to send request", err.Error())
			return
		}

		response := &rsaDecryptResponse{}
		respBytes, _, err := receiveBytes(conn)
		if err != nil {
			t.Error("rsaDecryptClient: invalid response", err.Error())
			return
		}

		err = decodeData(respBytes, response)

		if response.Status != expectedStatus {
			t.Error("rsaDecryptClient: unexpected status from server")
			return
		}

		result <- response.Data
	}
}

func makeUnpaddedRSADecryptOracle(
	host string, port int, pubKey *rsaPublic,
	t *testing.T, expectedStatus decryptStatus) func(ct []byte) []byte {
	//doesn't need to be secure
	randGen := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	return func(ct []byte) []byte {
		blinder := big.NewInt(0).Rand(randGen, pubKey.N)
		gcd, invBlinder, _ := extEuclidean(blinder, pubKey.N)

		one := big.NewInt(1)
		for gcd.Cmp(one) != 0 {
			blinder = big.NewInt(0).Rand(randGen, pubKey.N)
			gcd, invBlinder, _ = extEuclidean(blinder, pubKey.N)
		}

		encBlinder, err := rsaEncrypt(pubKey, blinder.Bytes())
		if err != nil {
			t.Error("unpadded rsa decrypt oracle:", err.Error())
			return nil
		}
		ctInt := newBigIntFromBytes(ct)
		blindedCT := new(big.Int).Mul(ctInt, newBigIntFromBytes(encBlinder))
		blindedCT.Mod(blindedCT, pubKey.N)
		blindedCTBytes := blindedCT.Bytes()

		result := make(chan []byte)
		f := makeRsaDecryptClient(t, allowed, result)
		go udpClient(host, port, func(conn *net.UDPConn) { f(conn, blindedCTBytes) })
		blindedBytes, ok := <-result
		if !ok {
			t.Error("client exited prematurely")
			return nil
		}

		blindedPT := new(big.Int).SetBytes(blindedBytes)
		pt := new(big.Int).Mul(blindedPT, invBlinder)
		pt.Mod(pt, pubKey.N)

		return pt.Bytes()
	}
}
