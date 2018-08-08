package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"cryptopals/gomd4"
	"cryptopals/gosha1"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type editfunction (func(ct []byte, offset uint64, newData []byte) []byte)

func makeEditCTR(ctrKey []byte, nonce, ctrStart uint64) editfunction {
	n := nonce
	ctr := ctrStart
	ciph := makeAES(ctrKey)
	return func(ct []byte, offset uint64, newText []byte) []byte {
		if offset+uint64(len(newText)) > uint64(len(ct)) {
			toAppend := offset + uint64(len(newText)) - uint64(len(ct))
			ct = append(ct, bytes.Repeat([]byte{0}, int(toAppend))...)
		}
		editKs := getKeyStreamOffsetLen(n, ctr, offset, uint64(len(newText)), ciph)
		editCt := xor(newText, editKs)
		result := make([]byte, len(ct))
		copy(result, ct)
		copy(result[offset:], editCt)
		return result
	}
}

func getKeyStreamOffsetLen(nonce, ctrStart, off, length uint64, ciph cipher.Block) []byte {
	var ks []byte
	bs := uint64(ciph.BlockSize())
	startBlock := off / bs
	endBlock := (off + length) / bs
	for b := startBlock; b <= endBlock; b++ {
		ks = append(ks, getKeyStream(nonce, ctrStart+b, ciph)...)
	}
	start := off % bs
	return ks[start : start+length]
}

func recoverCTRPlaintext(ct []byte, editf editfunction) []byte {
	newPT := bytes.Repeat([]byte{'A'}, len(ct))
	newCT := editf(ct, 0, newPT)
	ks := xor(newPT, newCT)
	return xor(ct, ks)
}

func makeCTREncryptorChecker() (stringEncryptor, stringDecryptCheckAdmin) {
	key := randKey(aes.BlockSize)
	ciph := makeAES(key)
	ctr := uint64(0)
	nonce := big.NewInt(0).SetBytes(randKey(2)).Uint64()
	enc := func(in string) []byte {
		prefix := "comment1=cooking%20MCs;userdata="
		suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
		in = strings.Replace(in, ";", "%3B", -1)
		in = strings.Replace(in, "=", "%3D", -1)
		pt := make([]byte, len(prefix)+len(in)+len(suffix))
		copy(pt, prefix)
		copy(pt[len(prefix):], in)
		copy(pt[len(prefix)+len(in):], suffix)
		return ctrEncrypt(pt, nonce, ctr, ciph)
	}

	decr := func(in []byte) bool {
		pt := ctrDecrypt(in, nonce, ctr, ciph)
		return strings.Contains(string(pt), ";admin=true;")
	}
	return enc, decr
}

func makeCBCiVkeyEncryptorChecker() (stringEncryptor, func(in []byte) (bool, error)) {
	key := randKey(aes.BlockSize)
	ciph := makeAES(key)
	enc := func(in string) []byte {
		prefix := "comment1=cooking%20MCs;userdata="
		suffix := ";comment2=%20like%20a%20pound%20of%20bacon"
		in = strings.Replace(in, ";", "%3B", -1)
		in = strings.Replace(in, "=", "%3D", -1)
		pt := make([]byte, len(prefix)+len(in)+len(suffix))
		copy(pt, prefix)
		copy(pt[len(prefix):], in)
		copy(pt[len(prefix)+len(in):], suffix)
		padded := pkcs7Pad([]byte(pt), ciph.BlockSize())
		return cbcEncrypt(padded, key, ciph)
	}

	decr := func(in []byte) (bool, error) {
		padded := cbcDecrypt(in, key, ciph)
		pt, err := pkcs7Unpad(padded)
		if err != nil {
			return false, errors.New(base64Encode(pt))
		}
		for _, c := range pt {
			if c < '\x21' || c > '\x7e' {
				return false, errors.New(base64Encode(pt))
			}
		}
		return strings.Contains(string(pt), ";admin=true;"), nil
	}
	return enc, decr
}

func recoverCBCiVKey(enc stringEncryptor, decr func(in []byte) (bool, error)) []byte {
	bs := aes.BlockSize
	msg := strings.Repeat("A", bs*3)
	zeros := make([]byte, bs)
	ct := enc(msg)
	myblocks := append(ct[:bs], zeros...)
	myblocks = append(myblocks, ct...)
	_, err := decr(myblocks)
	if err != nil {
		pt := base64Decode(err.Error())
		return xor(pt[:bs], pt[2*bs:3*bs])
	}
	return nil
}

func makeSha1HasherVerifier() (func(m []byte) []byte, func(m, s []byte) bool) {
	key := randKey(16)
	hasher := func(msg []byte) []byte {
		h := gosha1.New()
		h.Write(key)
		h.Write(msg)
		sum := h.Sum(nil)
		return sum
	}
	verifier := func(msg, shasum []byte) bool {
		sum := hasher(msg)
		return hmac.Equal(sum, shasum)
	}
	return hasher, verifier
}

func sha1Padding(msgLen uint64) []byte {
	bs := uint64(64)
	howmany := uint64(0)
	if msgLen%bs < 56 {
		howmany = 56 - msgLen%bs
	} else {
		howmany = bs + 56 - msgLen%bs
	}
	pad := make([]byte, howmany+8)
	pad[0] = 0x80
	padLen := len(pad)
	lenbits := msgLen << 3
	pad[padLen-8] = byte(lenbits >> 56)
	pad[padLen-7] = byte(lenbits >> 48)
	pad[padLen-6] = byte(lenbits >> 40)
	pad[padLen-5] = byte(lenbits >> 32)
	pad[padLen-4] = byte(lenbits >> 24)
	pad[padLen-3] = byte(lenbits >> 16)
	pad[padLen-2] = byte(lenbits >> 8)
	pad[padLen-1] = byte(lenbits)
	return pad
}

func lengthExtensionKeyedSha1(keyLen int, origHash, origMsg, toAppend []byte) (forged []byte, newHash []byte) {
	hh := gosha1.New()
	glue := sha1Padding(uint64(keyLen + len(origMsg)))
	hh.Reinit(origHash, uint64(keyLen+len(origMsg)+len(glue)))
	hh.Write(toAppend)
	newHash = hh.Sum(nil)
	forged = append(forged, origMsg...)
	forged = append(forged, glue...)
	forged = append(forged, toAppend...)
	return forged, newHash
}

func makeMd4HasherVerifier() (func(m []byte) []byte, func(m, s []byte) bool) {
	key := randKey(16)
	hasher := func(msg []byte) []byte {
		h := gomd4.New()
		h.Write(key)
		h.Write(msg)
		sum := h.Sum(nil)
		return sum
	}
	verifier := func(msg, shasum []byte) bool {
		sum := hasher(msg)
		return hmac.Equal(sum, shasum)
	}
	return hasher, verifier
}

func md4Padding(msgLen uint64) []byte {
	bs := uint64(64)
	howmany := uint64(0)
	if msgLen%bs < 56 {
		howmany = 56 - msgLen%bs
	} else {
		howmany = bs + 56 - msgLen%bs
	}
	pad := make([]byte, howmany+8)
	pad[0] = 0x80
	padLen := len(pad)
	lenbits := msgLen << 3
	pad[padLen-1] = byte(lenbits >> 56)
	pad[padLen-2] = byte(lenbits >> 48)
	pad[padLen-3] = byte(lenbits >> 40)
	pad[padLen-4] = byte(lenbits >> 32)
	pad[padLen-5] = byte(lenbits >> 24)
	pad[padLen-6] = byte(lenbits >> 16)
	pad[padLen-7] = byte(lenbits >> 8)
	pad[padLen-8] = byte(lenbits)
	return pad
}

func lengthExtensionKeyedMd4(keyLen int, origHash, origMsg, toAppend []byte) (forged []byte, newHash []byte) {
	hh := gomd4.New()
	glue := md4Padding(uint64(keyLen + len(origMsg)))
	hh.Reinit(origHash, uint64(keyLen+len(origMsg)+len(glue)))
	hh.Write(toAppend)
	newHash = hh.Sum(nil)
	forged = append(forged, origMsg...)
	forged = append(forged, glue...)
	forged = append(forged, toAppend...)
	return forged, newHash
}

func hmacSha1(key, msg []byte) []byte {
	if len(key) > sha1.BlockSize {
		h := sha1.Sum(key)
		key = h[:]
	}
	var zeros [64]byte
	if len(key) < sha1.BlockSize {
		key = append(key, zeros[:sha1.BlockSize-len(key)]...)
	}
	opad := bytes.Repeat([]byte{0x5c}, sha1.BlockSize)
	ipad := bytes.Repeat([]byte{0x36}, sha1.BlockSize)
	keyxoropad := xor(key, opad)
	keyxoripad := xor(key, ipad)
	outh := sha1.New()
	inh := sha1.New()
	inh.Write(keyxoripad)
	inh.Write(msg)
	outh.Write(keyxoropad)
	outh.Write(inh.Sum(nil))
	return outh.Sum(nil)
}

func insecureCompare(in1, in2 []byte, delay time.Duration) bool {
	if len(in1) != len(in2) {
		return false
	}

	for i := range in1 {
		if in1[i] != in2[i] {
			return false
		}
		time.Sleep(delay)
	}
	return true
}

func makeHTTPHmacFileServer(port uint16, delay time.Duration) func() {
	type cacheEntry struct {
		fname   string
		content []byte
	}

	cachedFile := cacheEntry{
		"",
		[]byte{},
	}

	return func() {
		key := []byte("YELLOW SUBMARINE")
		hmacFileHandler := func(resp http.ResponseWriter, req *http.Request) {
			req.ParseForm()

			if req.Form == nil || len(req.Form["file"]) == 0 || len(req.Form["signature"]) == 0 {
				resp.WriteHeader(400)
				return
			}

			fname := req.Form["file"][0]

			if cachedFile.fname != fname {
				cachedFile.fname = fname
				cachedFile.content = readFile(fname)
			}

			signature := hexDecode(req.Form["signature"][0])
			if insecureCompare(signature, hmacSha1(key, cachedFile.content), delay) {
				resp.WriteHeader(200)
				return
			}
			resp.WriteHeader(500)
		}

		http.HandleFunc("/test", hmacFileHandler)
		http.ListenAndServe("localhost:"+strconv.Itoa(int(port)), nil)
	}
}

func timeIt(url string) time.Duration {
	start := time.Now()
	resp, err := http.DefaultClient.Get(url)
	elapsed := time.Since(start)
	if err != nil {
		log.Print("calling", url, err.Error())
	}
	defer resp.Body.Close()

	return elapsed
}

func findHmacSha1Timing(filename, urlbase string, delay time.Duration) []byte {
	const numSamples = 3
	guessMac := make([]byte, sha1.Size)

	urlString := urlbase + "?file=" + filename + "&signature="

	for i := 0; i < sha1.Size; i++ {

		found := false
		url := urlString + hexEncode(guessMac)
		baseline := timeIt(url)
		var trial time.Duration

		for b := 1; b < 256; b++ {
			fmt.Printf("\rSeen: % x", guessMac)
			guessMac[i] = byte(b)
			url = urlString + hexEncode(guessMac)
			trial = timeIt(url)

			if trial-baseline > delay/2 {
				found = true
				break
			}

		}

		if !found {
			guessMac[i] = 0
		}

		fmt.Printf("\nbase: %f\nbest: %f\n", float64(baseline)/1.0e6, float64(trial)/1.0e6)
	}
	return guessMac
}
