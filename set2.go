package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net/url"
	"strconv"
	"strings"
)

func pkcs7Pad(in []byte, bs int) []byte {
	out := make([]byte, len(in), bs*(len(in)/bs+1))
	copy(out, in)
	remain := bs - len(in)%bs
	out = append(out, bytes.Repeat([]byte{byte(remain)}, remain)...)
	return out
}

func newError(s string) error {
	return errors.New(s)
}

func pkcs7Unpad(in []byte) ([]byte, error) {
	errStr := "Invalid padding"
	if len(in) == 0 {
		return nil, newError(errStr)
	}

	lastbyte := in[len(in)-1]

	if int(lastbyte) == 0 || int(lastbyte) > len(in) {
		return nil, newError(errStr)
	}
	expectedPad := bytes.Repeat([]byte{lastbyte}, int(lastbyte))
	padStart := len(in) - int(lastbyte)
	observedPad := in[padStart:]
	if bytes.Equal(observedPad, expectedPad) {
		return in[:padStart], nil
	}
	return nil, newError(errStr)
}

func ecbEncrypt(pt []byte, ciph cipher.Block) []byte {
	return ecbProcessBlocks(pt, ciph, false)
}

func cbcProcessBlocks(in, iv []byte, ciph cipher.Block, isDecryption bool) []byte {
	bs := ciph.BlockSize()
	if len(iv) != bs {
		panic("iv size mismatch")
	}

	prev := iv
	out := make([]byte, len(in))
	for i := 0; i < len(in); i += ciph.BlockSize() {
		if isDecryption {
			tmp := ecbDecrypt(in[i:i+bs], ciph)
			copy(out[i:i+bs], xor(tmp, prev))
			prev = in[i : i+bs]
		} else {
			tmp := ecbEncrypt(xor(in[i:i+bs], prev), ciph)
			copy(out[i:i+bs], tmp)
			prev = out[i : i+bs]
		}
	}

	return out
}

func cbcEncrypt(pt, iv []byte, ciph cipher.Block) []byte {
	return cbcProcessBlocks(pt, iv, ciph, false)
}

func cbcDecrypt(ct, iv []byte, ciph cipher.Block) []byte {
	return cbcProcessBlocks(ct, iv, ciph, true)
}

func randKey(n int) []byte {
	key := make([]byte, n)
	rand.Read(key)
	return key
}

func makeAES(key []byte) cipher.Block {
	ciph, err := aes.NewCipher(key)
	if err != nil {
		panic("cipher error:" + err.Error())
	}
	return ciph
}

type oracle func([]byte) []byte

func makeEncryptionOracle(keySize int) oracle {
	return func(in []byte) []byte {
		ciph := makeAES(randKey(keySize))
		prefixLen := 5 + mathrand.Intn(6)
		suffixLen := 5 + mathrand.Intn(6)
		pt := make([]byte, prefixLen+len(in)+suffixLen)
		copy(pt[:prefixLen], randKey(prefixLen))
		copy(pt[prefixLen:prefixLen+len(in)], in)
		copy(pt[prefixLen+len(in):], randKey(suffixLen))
		pt = pkcs7Pad(pt, ciph.BlockSize())
		var out []byte

		if mathrand.Intn(2) == 0 {
			out = ecbEncrypt(pt, ciph)
		} else {
			out = cbcEncrypt(pt, randKey(ciph.BlockSize()), ciph)
		}

		return out
	}
}

//cbcDetectOracle : (func ([]byte) -> []byte) -> bool
// true: the last run produced cbc
// false: the las run produced ecb
func makeCBCDetectOracle(blockSize int) func(oracle) bool {
	data := bytes.Repeat([]byte{'\x42'}, blockSize*3)
	out := func(encryptor oracle) bool {
		res, _ := detectECB(encryptor(data), blockSize)
		return !res
	}
	return out
}

func makePayloadEncryptionOracle(pl string, ciph cipher.Block) oracle {
	payload := base64Decode(pl)
	return func(in []byte) []byte {
		//time.Sleep(200 * time.Microsecond)
		pt := make([]byte, len(in))
		copy(pt, in)
		pt = append(pt, payload...)
		pt = pkcs7Pad(pt, ciph.BlockSize())
		return ecbEncrypt(pt, ciph)
	}
}

func ecbDecrypt1by1(encryptor oracle) []byte {
	pt := []byte{'A'}
	lenOne := len(encryptor(pt))
	blockLen := 0
	for inLen := 2; ; inLen++ {
		pt = append(pt, 'A')
		thisLen := len(encryptor(pt))
		blockLen = thisLen - lenOne
		if blockLen != 0 {
			break
		}
	}

	isECB, _ := detectECB(encryptor(bytes.Repeat([]byte{'A'}, 2*blockLen)), blockLen)

	if !isECB {
		fmt.Print("no ecb detected\n")
		return nil
	}

	makeDictionary := func(known []byte) map[string]byte {
		blocks := make(map[string]byte)
		craft := bytes.Repeat([]byte{'A'}, blockLen)
		craft = append(craft, known...)
		craft = append(craft, '?')
		craft = craft[len(craft)-blockLen:]
		for c := 0; c < 256; c++ {
			craft[blockLen-1] = byte(c)
			ct := string(encryptor(craft)[:blockLen])
			blocks[ct] = byte(c)
		}
		return blocks
	}

	pt = []byte("")
	limit := len(encryptor([]byte{}))
	for i := 0; i < limit; i++ {
		blocks := makeDictionary(pt)
		ct := encryptor(bytes.Repeat([]byte{'A'}, blockLen-len(pt)%blockLen-1))
		skip := i / blockLen * blockLen
		v := blocks[string(ct[skip:skip+blockLen])]
		//fmt.Printf("%c", v)
		pt = append(pt, v)
	}

	return pt
}

func kvParse(cookie string) url.Values {
	vals, err := url.ParseQuery(cookie)
	if err != nil {
		panic("invalid cookie")
	}
	return vals
}

func profileFor(email string) string {
	vals := make(url.Values)
	vals.Set("email", email)
	vals.Set("uid", strconv.Itoa(9+mathrand.Intn(90)))
	vals.Set("role", "user")
	return vals.Encode()
}

func makeProfileCiphers() (func(string) string, func(string) string) {
	ciph := makeAES(randKey(aes.BlockSize))
	encryptor := func(email string) string {
		ct := ecbEncrypt(pkcs7Pad([]byte(profileFor(email)), ciph.BlockSize()), ciph)
		return base64Encode(ct)
	}
	decryptor := func(in string) string {
		cipherText := base64Decode(in)
		v, _ := pkcs7Unpad(ecbDecrypt(cipherText, ciph))
		return string(v)
	}
	return encryptor, decryptor
}

func makeAdminProfile(encrypt func(string) string) string {
	//craft := "email=aldocassol" + "%40bar.com&role=" + "user&uid=26ppppp"
	craft1 := "aldocassol@bar.com"
	//craf2 := "email=foo%40bxxx" + "admin&role=user&" + "uid=26pppppppppp"
	craft2 := "foo@bxxxadmin"

	ct1 := base64Decode(encrypt(craft1))
	ct2 := base64Decode(encrypt(craft2))
	var newct []byte
	newct = append(newct, ct1[:2*aes.BlockSize]...)
	newct = append(newct, ct2[aes.BlockSize:]...)

	return base64Encode(newct)
}

func makeRandomHeadPayloadEncryptionOracle(pl string, ciph cipher.Block) oracle {
	header := make([]byte, mathrand.Intn(1000))
	rand.Read(header)
	payload := base64Decode(pl)
	return func(in []byte) []byte {
		pt := make([]byte, len(header)+len(in)+len(payload))
		copy(pt, header)
		copy(pt[len(header):], in)
		copy(pt[len(header)+len(in):], payload)
		pt = pkcs7Pad(pt, ciph.BlockSize())
		return ecbEncrypt(pt, ciph)
	}
}

func fixRandHeaderOracle(encryptor oracle) oracle {
	var pt []byte
	lenNil := len(encryptor(pt))
	blockLen := 0
	for {
		pt = append(pt, 'A')
		blockLen = len(encryptor(pt)) - lenNil
		if blockLen != 0 {
			break
		}
	}

	var isECB bool
	var boundary int
	pt = nil
	for {
		pt = append(pt, 'A')
		isECB, boundary = detectECB(encryptor(pt), blockLen)
		if isECB {
			break
		}
	}

	bytesToBoundary := len(pt) % blockLen

	return func(in []byte) []byte {
		x := bytes.Repeat([]byte{'A'}, bytesToBoundary+2*blockLen)
		x = append(x, in...)
		return encryptor(x)[boundary+2*blockLen:]
	}

}

type stringEncryptor func(string) []byte
type stringDecryptCheckAdmin func([]byte) bool

func makeCBCEncryptorChecker() (stringEncryptor, stringDecryptCheckAdmin) {
	key := randKey(aes.BlockSize)
	ciph := makeAES(key)
	iv := make([]byte, ciph.BlockSize())
	rand.Read(iv)
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
		return cbcEncrypt(padded, iv, ciph)
	}

	decr := func(in []byte) bool {
		padded := cbcDecrypt(in, iv, ciph)
		pt, err := pkcs7Unpad(padded)
		if err != nil {
			panic("Error: " + err.Error())
		}
		return strings.Contains(string(pt), ";admin=true;")
	}
	return enc, decr
}
