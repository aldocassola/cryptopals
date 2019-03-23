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
	"strings"
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

func makeRSADecryptClient(
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
		f := makeRSADecryptClient(t, allowed, result)
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
	h.Write(msg)
	hmsg := h.Sum(nil)[:h.Size()]
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

	h.Write(msg)
	hh := h.Sum(nil)[:h.Size()]
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
	diff := new(big.Int)

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
		h.Reset()
		//the maximum possible valid block
		maxPkcs15Block, err := getForgeBlock(modLen, padLen, h, msg, 0xff)
		if err != nil {
			return nil, err
		}
		h.Reset()
		numBlock := newBigIntFromBytes(pkcs15Block)
		maxNumBlock := newBigIntFromBytes(maxPkcs15Block)
		sigX, _ = cubeRoot(numBlock)
		maxSigX, _ := cubeRoot(maxNumBlock)
		//if there is no cube root interval, reduce the pad length
		diff.Sub(maxSigX, sigX)
		if diff.Sign() > 0 {
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

func defaultDSAParams() *dsaParams {
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

	return &dsaParams{
		g: newBigIntFromBytes(hexDecode(givenG)),
		p: newBigIntFromBytes(hexDecode(givenP)),
		q: newBigIntFromBytes(hexDecode(givenQ)),
		h: sha1.New,
	}
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
	priv := big.NewInt(0)
	var err error
	for priv.Sign() == 0 {
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

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func dsaSign(priv *dsaPrivate, msg []byte) (*dsaSignature, error) {
	one := big.NewInt(1)
	params := priv.params
	h := priv.params.h()
	qlen := (params.q.BitLen() + 7) / 8
	hlen := minInt(h.Size(), qlen)
	h.Write(msg)
	hnum := newBigIntFromBytes(h.Sum(nil)[:hlen])

	k := big.NewInt(0)
	var err error
	var sig *dsaSignature
	for {
		for k.Sign() == 0 ||
			k.Cmp(one) == 0 {
			//k could be f(x, h(msg)), but make it random
			k, err = rand.Int(rand.Reader, params.q)
			if err != nil {
				return nil, err
			}
		}

		sig, err = dsaDoSign(priv, hnum, k)
		if err != nil {
			continue
		}
		break
	}

	return sig, nil
}

func dsaDoSign(priv *dsaPrivate, hnum, k *big.Int) (*dsaSignature, error) {
	r := big.NewInt(0)
	s := big.NewInt(0)
	params := priv.params
	_, kinv, _ := extEuclidean(k, params.q)
	r.Exp(params.g, k, params.p)
	r.Mod(r, params.q)
	//Should check if r is zero, but Problem 45
	//needs check to be off
	// if r.Cmp(zero) == 0 {
	// 	return nil, errors.New("")
	// }

	s.Mul(priv.x, r)
	s.Add(s, hnum)
	s.Mul(s, kinv)
	s.Mod(s, params.q)
	if s.Sign() == 0 {
		return nil, errors.New("")
	}

	minLen := minInt(params.h().Size(), (params.q.BitLen()+7)/8)
	return &dsaSignature{
		r: padToLenLeft(r.Bytes(), minLen),
		s: padToLenLeft(s.Bytes(), minLen)}, nil
}

func dsaVerify(pubKey *dsaPublic, msg []byte, sig *dsaSignature) bool {
	params := pubKey.params
	r := newBigIntFromBytes(sig.r)
	s := newBigIntFromBytes(sig.s)
	//should check if r is zero but problem 45 needs not to
	if //r.Cmp(zero) <= 0 || r.Cmp(params.q) >= 0 ||
	s.Sign() <= 0 || s.Cmp(params.q) >= 0 {
		return false
	}

	_, w, _ := extEuclidean(s, params.q)
	h := params.h()
	qlen := (pubKey.params.q.BitLen() + 7) / 8
	hlen := minInt(h.Size(), qlen)
	h.Write(msg)
	hmsg := newBigIntFromBytes(h.Sum(nil)[:hlen])
	u1 := new(big.Int).Mul(w, hmsg)
	u1.Mod(u1, params.q)

	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, params.q)

	gu1 := bigPowMod(params.g, u1, params.p)
	yu2 := bigPowMod(pubKey.y, u2, params.p)
	v := new(big.Int).Mul(gu1, yu2)
	v.Mod(v, params.p).Mod(v, params.q)
	return v.Cmp(r) == 0
}

func getDSAPrivateFromK(params *dsaParams, sig *dsaSignature, hmsg []byte, k *big.Int) *dsaPrivate {
	q := params.q
	hnum := new(big.Int).SetBytes(hmsg)
	r := newBigIntFromBytes(sig.r)
	_, rinv, _ := extEuclidean(r, q)
	s := newBigIntFromBytes(sig.s)
	x := new(big.Int)

	x.Mul(s, k).Mod(x, q)
	x.Sub(x, hnum).Mod(x, q)
	x.Mul(x, rinv).Mod(x, q)

	return &dsaPrivate{x: x, params: params}
}

func loopKDSAPrivate(pubKey *dsaPublic, sig *dsaSignature, hmsg, target []byte) *dsaPrivate {
	params := pubKey.params
	lim := 65537
	bigk := new(big.Int)
	var priv *dsaPrivate

	for k := 0; k < lim; k++ {
		bigk.SetInt64(int64(k))
		priv = getDSAPrivateFromK(params, sig, hmsg, bigk)
		cfp := sha1.Sum([]byte(priv.x.Text(16)))

		if bytes.Equal(cfp[:], target) {
			return priv
		}
	}
	return nil
}

type dsaSignedMessage struct {
	msg  string
	hmsg string
	r    string
	s    string
}

func makeDSASignedMessages(filename string) []dsaSignedMessage {
	data := string(readFile(filename))
	lines := strings.FieldsFunc(data, func(r rune) bool {
		return r == '\n' || r == '\r'
	})
	messages := make([]dsaSignedMessage, len(lines)/4)
MessageParse:
	for i := 0; i < len(lines); i += 4 {
		for j := 0; j < 4; j++ {
			keyval := strings.Split(lines[i+j], ":")
			key := keyval[0]
			val := keyval[1]

			switch key {
			case "msg":
				messages[i/4].msg = val[1:]
			case "s":
				messages[i/4].s = val[1:]
			case "r":
				messages[i/4].r = val[1:]
			case "m":
				messages[i/4].hmsg = val[1:]
			default:
				continue MessageParse
			}
		}
	}
	return messages
}

func findRepeatedDSAK(messages []dsaSignedMessage) [][]dsaSignedMessage {
	dupes := make([][]dsaSignedMessage, 0)
	rmap := make(map[string][]int)
	for i, msg := range messages {
		v, ok := rmap[msg.r]
		if !ok {
			ii := make([]int, 1)
			ii[0] = 1
			rmap[msg.r] = []int{i}
		} else {
			v = append(v, i)
			rmap[msg.r] = v
		}

	}

	for _, v := range rmap {
		if len(v) > 1 {
			reps := make([]dsaSignedMessage, len(v))
			for i, idx := range v {
				reps[i] = messages[idx]
			}
			dupes = append(dupes, reps)
		}
	}
	return dupes
}

func findDSPrivateFromRepeatedK(sameKMsgs []dsaSignedMessage, params *dsaParams) *dsaPrivate {
	if len(sameKMsgs) < 2 {
		return nil
	}
	m1 := sameKMsgs[0]
	m2 := sameKMsgs[1]
	hmsg1, _ := new(big.Int).SetString(m1.hmsg, 16)
	hmsg2, _ := new(big.Int).SetString(m2.hmsg, 16)
	s1, _ := new(big.Int).SetString(m1.s, 10)
	s2, _ := new(big.Int).SetString(m2.s, 10)

	mdiff := new(big.Int).Sub(hmsg1, hmsg2)
	mdiff.Mod(mdiff, params.q)
	sdiff := new(big.Int).Sub(s1, s2)
	sdiff.Mod(sdiff, params.q)
	_, sdiffInv, _ := extEuclidean(sdiff, params.q)
	k := new(big.Int).Mul(mdiff, sdiffInv)
	k.Mod(k, params.q)

	r1, _ := new(big.Int).SetString(m1.r, 10)
	sig := &dsaSignature{r: r1.Bytes(), s: s1.Bytes()}

	return getDSAPrivateFromK(params, sig, hmsg1.Bytes(), k)
}

func getBadDSAParams(paramGen func() *dsaParams, badG *big.Int) *dsaParams {
	params := paramGen()
	params.g.Set(badG)
	return params
}

func makeDSAMagicSigOracle(pub *dsaPublic) func([]byte) *dsaSignature {
	params := pub.params
	h := params.h()
	return func(msg []byte) *dsaSignature {
		r := new(big.Int)
		s := new(big.Int)
		h.Write(msg)
		y := new(big.Int).Set(pub.y)
		z := newBigIntFromBytes(h.Sum(nil)[:h.Size()])
		_, zinv, _ := extEuclidean(z, params.q)
		r.Exp(y, z, params.p).Mod(r, params.q)
		s.Mul(r, zinv).Mod(s, params.q)
		minLen := minInt(h.Size(), (params.q.BitLen()+7)/8)

		return &dsaSignature{
			r: padToLenLeft(r.Bytes(), minLen),
			s: padToLenLeft(s.Bytes(), minLen),
		}
	}
}

func makeRSAParityOracle(priv *rsaPrivate) func([]byte) bool {
	two := big.NewInt(2)
	return func(ct []byte) bool {
		pt, err := rsaDecrypt(priv, ct)
		if err != nil {
			panic(err)
		}
		ptN := new(big.Int).SetBytes(pt)
		return ptN.Mod(ptN, two).Sign() == 0
	}
}

func decryptWithRSAParityOracle(pub *rsaPublic, ct []byte, isPTEven func([]byte) bool) []byte {
	twoCT, err := rsaEncrypt(pub, big.NewInt(2).Bytes())
	if err != nil {
		panic(err)
	}

	ctNum := newBigIntFromBytes(ct)
	eTwo := newBigIntFromBytes(twoCT)
	mid := new(big.Int)
	low := big.NewInt(0)
	up := new(big.Int).Set(pub.N)
	i := 0

	for low.Cmp(up) < 0 {
		fmt.Printf("\r(%04d)up=%s", i, up.Bytes())
		ctNum.Mul(ctNum, eTwo).Mod(ctNum, pub.N)
		mid.Add(up, low).Rsh(mid, 1)

		if isPTEven(ctNum.Bytes()) { //didn't wrap around, decrease upper bound
			up.Set(mid)
		} else { //wrapped around, increase low bound
			low.Set(mid)
		}
		i++
	}

	pt := up.Bytes()
	for j := 0; j < 256; j++ {
		pt[len(pt)-1] = byte(j)
		fmt.Printf("\r(%04d)up=%s", i+j, pt)
		ctp, err := rsaEncrypt(pub, pt)
		if err != nil {
			panic(err)
		}
		if bytes.Equal(ct, ctp) {
			break
		}
	}

	fmt.Printf("\n(****)up=%s\n", pt)
	return pt
}

func makePKCS1v15ConformityOracle(priv *rsaPrivate) func([]byte) bool {
	return func(in []byte) bool {
		if len(in) == 0 {
			return false
		}

		pt, err := rsaDecrypt(priv, in)
		if err != nil {
			return false
		}

		pt = padToLenLeft(pt, (priv.n.BitLen()+7)/8)

		if len(pt) < 2 || pt[0] != 0 || pt[1] != 2 {
			return false
		}

		if bytes.Count(pt[2:11], []byte{0}) > 0 {
			return false
		}

		if bytes.Count(pt[11:], []byte{0}) == 0 {
			return false
		}

		return true
	}
}

func randNonzero(out []byte) {
	rand.Read(out)
	for bytes.ContainsAny(out, "\x00") {
		rand.Read(out)
	}
}

func padPKCS1v15(in []byte, mLen int) ([]byte, error) {
	errModTooSmall := errors.New("modulus length is too small")
	if len(in) > mLen-11 {
		return nil, errModTooSmall
	}

	psLen := mLen - 3 - len(in)
	padded := make([]byte, mLen)
	padded[0], padded[1] = 0, 2
	randNonzero(padded[2 : 2+psLen])
	padded[2+psLen] = 0
	n := copy(padded[2+psLen+1:], in)
	if n != len(in) {
		return nil, errModTooSmall
	}

	return padded, nil
}

type interval struct {
	low  *big.Int
	high *big.Int
}

type intervals []*interval

type bbSearch struct {
	pub          *rsaPublic
	c0           *big.Int
	si           *big.Int
	B            *big.Int
	mi           intervals
	isConforming func([]byte) bool
	count        uint64
}

func (s *bbSearch) String() string {
	hd := fmt.Sprintf("{ n: %s, c0: %s, s1: %s, m0: [ ",
		s.pub.N, s.c0, s.si)
	var intvals string
	for i, iv := range s.mi {
		intvals += fmt.Sprintf("%d:{ low: %s, high: %s }", i, iv.low, iv.high)
		if i < len(s.mi)-1 {
			intvals += ", "
		}
	}
	intvals += " ] }"

	return hd + intvals
}

func newInterval(lo, hi *big.Int) *interval {
	return &interval{
		low:  new(big.Int).Set(lo),
		high: new(big.Int).Sub(hi, one),
	}
}

func rsaBlind(ct, s *big.Int, pub *rsaPublic) ([]byte, error) {
	blinder, err := rsaEncrypt(pub, s.Bytes())
	if err != nil {
		return nil, err
	}

	x := new(big.Int).Mul(newBigIntFromBytes(blinder), ct)
	return x.Mod(x, pub.N).Bytes(), nil
}

func newBBSearch(c0b []byte, pub *rsaPublic, isPKCS1v15 func([]byte) bool) *bbSearch {
	c0 := newBigIntFromBytes(c0b)
	b := new(big.Int).Lsh(one, uint(pub.N.BitLen()-16))
	twoB := new(big.Int).Add(b, b)
	threeB := new(big.Int).Add(twoB, b)

	s1 := new(big.Int).Div(pub.N, threeB)
	fmt.Printf("n/3B=%s\n", s1.String())

	for ; ; s1.Add(s1, one) {
		blinded, err := rsaBlind(c0, s1, pub)
		if err != nil {
			panic("initial blinding failed!")
		}

		if isPKCS1v15(blinded) {
			return &bbSearch{
				count:        1,
				pub:          pub,
				si:           s1,
				c0:           new(big.Int).Set(c0),
				mi:           intervals{newInterval(twoB, threeB)},
				B:            b,
				isConforming: isPKCS1v15,
			}
		}
	}
}

func (s *bbSearch) searchNext() {
	if len(s.mi) == 1 {
		s.si = s.searchOne()
	} else if len(s.mi) >= 2 {
		panic("found many intervals")
	} else {
		panic("found empty intervals")
	}
}

func (s *bbSearch) narrow() {}

func (s *bbSearch) searchOne() *big.Int {
	isPKCS1v15 := s.isConforming
	si := new(big.Int)
	a := s.mi[0].low
	b := s.mi[0].high
	si1 := s.si
	twoB := new(big.Int).Add(s.B, s.B)
	threeB := new(big.Int).Add(twoB, s.B)
	bsi1 := new(big.Int).Mul(b, si1)
	ri := new(big.Int).Sub(bsi1, twoB)
	ri.Div(ri, s.pub.N)
	ri.Mul(two, ri)

	for ; ; ri.Add(ri, one) {
		rin := new(big.Int).Mul(ri, s.pub.N)
		siLow := new(big.Int).Add(twoB, rin)
		siLow.Div(siLow, b)
		siHi := new(big.Int).Add(threeB, rin)
		siHi.Div(siHi, a)

		for si.Set(siLow); si.Cmp(siHi) < 0; si.Add(si, one) {
			blinded, err := rsaBlind(s.c0, si, s.pub)
			if err != nil {
				panic("blinding failed!")
			}

			if isPKCS1v15(blinded) {
				return si
			}
		}
	}
}

func (s *bbSearch) searchMany() *bbSearch {
	return nil
}
