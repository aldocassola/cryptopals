package cryptopals

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"regexp"
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

type hashAlgorithm int

const (
	mD5    hashAlgorithm = md5.Size
	sHA1   hashAlgorithm = sha1.Size
	sHA256 hashAlgorithm = sha256.Size
	sHA384 hashAlgorithm = sha512.Size384
	sHA512 hashAlgorithm = sha512.Size
)

func lookupHashID(h hash.Hash) ([]byte, error) {
	alg := hashAlgorithm(h.Size())
	switch alg {
	case mD5:
		return []byte{
			0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
			0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10}, nil
	case sHA1:
		return []byte{
			0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b,
			0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}, nil
	case sHA256:
		return []byte{
			0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}, nil
	case sHA384:
		return []byte{
			0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}, nil
	case sHA512:
		return []byte{
			0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
			0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}, nil
	default:
		return nil, errors.New("unsopported hash type")
	}
}

func encodePKCS15(msg []byte, h hash.Hash, emLen int) ([]byte, error) {
	block := make([]byte, emLen)
	hmsg := h.Sum(msg)[:h.Size()]
	digestID, err := lookupHashID(h)
	if err != nil {
		return nil, err
	}
	digestID = append(digestID, hmsg...)
	tLen := len(digestID)
	if emLen < tLen+11 {
		return nil, errors.New("intended encoded message length too short")
	}
	psLen := emLen - tLen - 3
	copy(block, []byte{0, 1})
	copy(block[2:], bytes.Repeat([]byte{0xff}, psLen))
	block[psLen+2] = 0x0
	copy(block[psLen+3:], digestID)
	return block, nil
}

func rsaSign(privKey *rsaPrivate, msg []byte, h hash.Hash) ([]byte, error) {
	encoded, err := encodePKCS15(msg, h, len(privKey.n.Bytes()))
	if err != nil {
		return nil, err
	}

	encNum := newBigIntFromBytes(encoded)
	if encNum.Cmp(privKey.n) >= 0 {
		return nil, errors.New("message representative out of range")
	}

	sig := bigPowMod(encNum, privKey.d, privKey.n).Bytes()
	modLen := len(privKey.n.Bytes())
	sig = padToLenLeft(sig, modLen)

	return sig, nil
}

func rsaVerify(pubKey *rsaPublic, msg []byte, sig []byte, h hash.Hash) (bool, error) {
	modLen := len(pubKey.N.Bytes())
	if len(sig) != modLen {
		return false, errors.New("invalid signature")
	}

	sigNum := newBigIntFromBytes(sig)
	if sigNum.Cmp(pubKey.N) >= 0 {
		return false, errors.New("invalid signature")
	}

	m := bigPowMod(sigNum, pubKey.E, pubKey.N)
	mString := fmt.Sprintf("%x", padToLenLeft(m.Bytes(), modLen))
	algID, err := lookupHashID(h)
	if err != nil {
		return false, errors.New("unsopported algorithm")
	}

	hh := h.Sum(msg)[:h.Size()]
	//this is a bad check- it matches blocks that have too few (FF) bytes
	patt := fmt.Sprintf("0001(ff)+00%x%x", algID, hh)
	re, err := regexp.Compile(patt)
	if err != nil {
		return false, err
	}
	return re.MatchString(mString), nil
}

func padToLenLeft(b []byte, length int) []byte {
	if len(b) < length {
		b = append(bytes.Repeat([]byte{0}, length-len(b)), b...)
	}
	return b
}

func getForgeBlock(modulusLen, padLen int, asnStuff, hmsg []byte) ([]byte, error) {
	if 3+padLen+len(asnStuff)+len(hmsg) > modulusLen {
		return nil, errors.New("modulus length too short")
	}
	block := make([]byte, modulusLen)
	padBytes := bytes.Repeat([]byte{0xff}, padLen)
	copy(block, []byte{0, 1})
	copy(block[2:], padBytes)
	copy(block[2+padLen:], []byte{0})
	copy(block[3+padLen:], asnStuff)
	copy(block[3+padLen+len(asnStuff):], hmsg)
	return block, nil
}

func rsaPKCS15SignatureForge(msg []byte, h hash.Hash, pubKey *rsaPublic) ([]byte, error) {
	modLen := len(pubKey.N.Bytes())
	hashID, _ := lookupHashID(h)
	if modLen <= h.Size()+len(hashID)+4 {
		return nil, errors.New("modulus too small")
	}

	hmsg := h.Sum(msg)[:h.Size()]
	three := big.NewInt(3)
	one := big.NewInt(1)

	var sigX, cubedSig *big.Int
	padLen := 1
	var pkcs15Block []byte
	var err error
	zerostart := 3 + padLen + len(hashID) + len(hmsg)

	for zerostart < modLen {
		pkcs15Block, err = getForgeBlock(modLen, padLen, hashID, hmsg)
		if err != nil {
			return nil, err
		}
		numBlock := newBigIntFromBytes(pkcs15Block)
		sigX, _ = cubeRoot(numBlock)
		cubedSig = new(big.Int).Exp(sigX, three, nil)
		cubedBytes := padToLenLeft(cubedSig.Bytes(), modLen)

		//perfect cube found
		if bytes.Compare(
			cubedBytes[:zerostart],
			pkcs15Block[:zerostart]) == 0 {
			break
		}

		sigX.Add(sigX, one)
		cubedSig = new(big.Int).Exp(sigX, three, nil)
		cubedBytes = padToLenLeft(cubedSig.Bytes(), modLen)

		if bytes.Compare(
			cubedBytes[:zerostart],
			pkcs15Block[:zerostart]) == 0 {
			break
		}

		padLen++
		zerostart = 3 + padLen + len(hashID) + len(hmsg)
	}

	return padToLenLeft(sigX.Bytes(), modLen), nil
}

type dsaParams struct {
	g *big.Int
	p *big.Int
	q *big.Int
	h func() hash.Hash
}

func newDSAParams(Lbits, Nbits int, newH func() hash.Hash) (*dsaParams, error) {
	if Lbits%64 != 0 {
		return nil, errors.New("Invalid DSA prime length L")
	}
	hsize := newH().Size() * 8
	if Nbits > hsize {
		return nil, errors.New("Invalid parameter N, must be <= size of hash")
	}

	q, err := rand.Prime(rand.Reader, Nbits)
	if err != nil {
		return nil, err
	}

	zero := big.NewInt(0)
	one := big.NewInt(1)
	p, err := rand.Prime(rand.Reader, Lbits)
	if err != nil {
		return nil, err
	}
	pm1 := new(big.Int).Sub(p, one)
	for new(big.Int).Mod(pm1, q).Cmp(zero) == 0 {
		p, err = rand.Prime(rand.Reader, Lbits)
		if err != nil {
			return nil, err
		}
		pm1.Sub(p, one)
	}

	pm1dq := new(big.Int).Div(pm1, q)
	g := big.NewInt(1)
	for g.Cmp(one) == 1 {
		h := big.NewInt(0)
		for h.Cmp(zero) == 0 {
			h, err = rand.Int(rand.Reader, p)
			if err != nil {
				return nil, err
			}
		}

		g = bigPowMod(h, pm1dq, p)
	}

	return &dsaParams{
		h: newH,
		g: g,
		p: p,
		q: q}, nil
}

type dsaPublic struct {
	y      *big.Int
	params *dsaParams
}

type dsaPrivate struct {
	x      *big.Int
	params *dsaParams
}

type dsaKeyPair struct {
	public  *dsaPublic
	private *dsaPrivate
}

type dsaSignature struct {
	r []byte
	s []byte
}

func genDSAKeyPair(params *dsaParams) (*dsaKeyPair, error) {
	zero := big.NewInt(0)
	priv := big.NewInt(0)
	var err error
	for priv.Cmp(zero) == 0 {
		priv, err = rand.Int(rand.Reader, params.q)
		if err != nil {
			return nil, err
		}
	}

	pub := bigPowMod(params.g, priv, params.p)
	return &dsaKeyPair{
		public:  &dsaPublic{pub, params},
		private: &dsaPrivate{priv, params}}, nil
}

func dsaSign(priv *dsaPrivate, msg []byte) (*dsaSignature, error) {
	params := priv.params
	zero := big.NewInt(0)
	one := big.NewInt(1)
	k := big.NewInt(0)
	r := big.NewInt(0)
	s := big.NewInt(0)
	h := priv.params.h()
	var err error
	for {
		for k.Cmp(zero) == 0 ||
			k.Cmp(one) == 0 {
			k, err = rand.Int(rand.Reader, params.q)
			if err != nil {
				return nil, err
			}
		}

		_, kinv, _ := extEuclidean(k, params.q)

		r = bigPowMod(params.g, k, params.p)
		r.Mod(r, params.q)

		if r.Cmp(zero) == 0 {
			continue
		}

		hnum := newBigIntFromBytes(h.Sum(msg)[:h.Size()])
		xr := new(big.Int).Mul(priv.x, r)
		xr.Mod(xr, params.q)
		sum := new(big.Int).Add(hnum, xr)
		sum.Mod(sum, params.q)
		s = new(big.Int).Mul(kinv, sum)
		s.Mod(s, params.q)

		if s.Cmp(zero) == 0 {
			continue
		}

		break
	}

	return &dsaSignature{r: r.Bytes(), s: s.Bytes()}, nil
}
