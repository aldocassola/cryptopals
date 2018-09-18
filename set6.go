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
	"io"
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

func getForgeBlock(modulusLen, padLen int, h hash.Hash, msg []byte, fillByte byte) ([]byte, error) {
	if padLen <= 0 {
		return nil, errors.New("length must me greater than zero")
	}
	block, err := encodePKCS15(msg, h, modulusLen)
	if err != nil {
		return nil, err
	}
	asn1goop, err := lookupHashID(h)
	if err != nil {
		return nil, err
	}
	maxPadLen := modulusLen - h.Size() - len(asn1goop) - 3
	if padLen > maxPadLen {
		return nil, errors.New("requested pad length too long")
	}

	copy(block[2+padLen:], block[modulusLen-h.Size()-len(asn1goop)-1:])
	zerostart := 3 + padLen + len(asn1goop) + h.Size()
	fillBytes := bytes.Repeat([]byte{fillByte}, modulusLen)
	copy(block[zerostart:], fillBytes)

	return block, nil
}

func rsaPKCS15SignatureForge(msg []byte, h hash.Hash, pubKey *rsaPublic) ([]byte, error) {
	one := big.NewInt(1)
	modLen := len(pubKey.N.Bytes())
	hashID, err := lookupHashID(h)
	if err != nil {
		return nil, err
	}

	var sigX *big.Int
	padLen := modLen - h.Size() - len(hashID) - 4
	var pkcs15Block []byte

	//find the minimum pad length such that there exists a cube
	//root that yields the correct result.
	//We cube root the minimum and the maximum blocks with the right
	//prefix. If both cube roots are equal, none will give
	//a good block when cubed.
	for padLen >= 1 {
		//the target block
		pkcs15Block, err = getForgeBlock(modLen, padLen, h, msg, 0x00)
		if err != nil {
			return nil, err
		}
		//the maximum possible valid block
		maxPkcs15Block, err := getForgeBlock(modLen, padLen, h, msg, 0xff)
		if err != nil {
			return nil, err
		}
		numBlock := newBigIntFromBytes(pkcs15Block)
		maxNumBlock := newBigIntFromBytes(maxPkcs15Block)
		sigX, _ = cubeRoot(numBlock)
		maxSigX, _ := cubeRoot(maxNumBlock)
		//if there is no cube root interval, reduce the pad length
		diff := new(big.Int).Sub(maxSigX, sigX)
		if diff.Cmp(big.NewInt(0)) > 0 {
			log.Printf("found maximum valid pad len: %d, diff: %s", padLen, diff)
			break
		}

		padLen--
	}

	if padLen < 1 {
		return nil, errors.New("no valid signature exists")
	}

	//sigX has the largest n such that n^3 <= minblock
	//We know the length of the cube roots interval is at least one
	//Round up to get your signature
	return padToLenLeft(sigX.Add(sigX, one).Bytes(), modLen), nil
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

	one := big.NewInt(1)
	p := new(big.Int)
	q := new(big.Int)
	g := new(big.Int)
	rem := new(big.Int)
	h := new(big.Int)
	pBytes := make([]byte, Lbits/8)
	rnd := rand.Reader
	primeTests := 64
	var err error
	found := false

	for !found {
		fmt.Println("q")
		q, err = rand.Prime(rnd, Nbits)
		if err != nil {
			return nil, err
		}

		fmt.Print("p")
		for i := 0; i < 4*Lbits; i++ {
			if _, err = io.ReadFull(rnd, pBytes); err != nil {
				return nil, err
			}

			pBytes[0] |= 0x80
			pBytes[len(pBytes)-1] |= 0x01

			p.SetBytes(pBytes)
			rem.Mod(p, q)
			rem.Sub(rem, one)
			p.Sub(p, rem)
			if p.BitLen() < Lbits {
				fmt.Print("*")
				continue
			}

			if !p.ProbablyPrime(primeTests) {
				fmt.Print(".")
				continue
			}

			found = true
			break
		}
		if found == false {
			fmt.Println()
		}
	}

	fmt.Println(":)")
	pm1 := new(big.Int).Sub(p, one)
	pm1dq := new(big.Int).Div(pm1, q)
	fmt.Print("g")
	h.SetInt64(2)
	for {
		g.Exp(h, pm1dq, p)
		if g.Cmp(one) != 0 {
			break
		}
		h.Add(h, one)
		fmt.Print(".")
	}
	fmt.Println(":)")
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
	xr := new(big.Int)
	sum := new(big.Int)
	hnum := newBigIntFromBytes(h.Sum(msg)[:h.Size()])
	var err error
	for {
		for k.Cmp(zero) == 0 ||
			k.Cmp(one) == 0 {
			//k could be f(x, h(msg)), make it random
			k, err = rand.Int(rand.Reader, params.q)
			if err != nil {
				return nil, err
			}
		}

		_, kinv, _ := extEuclidean(k, params.q)
		r.Exp(params.g, k, params.p)
		r.Mod(r, params.q)

		if r.Cmp(zero) == 0 {
			continue
		}

		xr.Mul(priv.x, r)
		xr.Mod(xr, params.q)
		sum.Add(hnum, xr)
		sum.Mod(sum, params.q)
		s.Mul(kinv, sum)
		s.Mod(s, params.q)

		if s.Cmp(zero) == 0 {
			continue
		}

		break
	}

	return &dsaSignature{r: r.Bytes(), s: s.Bytes()}, nil
}

func dsaVerify(pubKey *dsaPublic, msg []byte, sig *dsaSignature) (bool, error) {
	zero := big.NewInt(0)
	params := pubKey.params
	r := newBigIntFromBytes(sig.r)
	s := newBigIntFromBytes(sig.s)
	if r.Cmp(zero) <= 0 || r.Cmp(params.q) > 0 ||
		s.Cmp(zero) <= 0 || s.Cmp(params.q) > 0 {
		return false, errors.New("invalid signature")
	}

	_, w, _ := extEuclidean(s, params.q)
	h := params.h()
	hmsg := newBigIntFromBytes(h.Sum(msg)[:h.Size()])
	u1 := new(big.Int).Mul(w, hmsg)
	u1.Mod(u1, params.q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, params.q)

	gu1 := bigPowMod(params.g, u1, params.p)
	yu2 := bigPowMod(pubKey.y, u2, params.p)
	v := new(big.Int).Mul(gu1, yu2)
	v.Mod(v, params.p)
	v.Mod(v, params.q)
	return v.Cmp(r) == 0, nil
}
