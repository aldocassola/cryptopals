package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
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

func pkcs7Unpad(in []byte) []byte {
	return in[:len(in)-int(in[len(in)-1])]
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
	return func(in []byte) []byte {
		payload := base64Decode(pl)
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

	pt = []byte("")
	limit := len(encryptor([]byte{}))
	for i := 0; i < limit; i++ {
		craft := bytes.Repeat([]byte{'A'}, blockLen)
		craft = append(craft, pt...)
		craft = append(craft, '?')
		craft = craft[len(craft)-blockLen:]
		blocks := makeDictionary(pt, blockLen, encryptor)
		ct := encryptor(bytes.Repeat([]byte{'A'}, blockLen-len(pt)%blockLen-1))
		skip := i / blockLen * blockLen
		v := blocks[string(ct[skip:skip+blockLen])]
		pt = append(pt, v)
	}

	return pt
}

func makeDictionary(known []byte, blockLen int, encryptor func([]byte) []byte) map[string]byte {
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

type profile struct {
	email string
	uid   uint16
	role  string
}

func kvParse(cookie string) string {
	pairs := strings.Split(cookie, "&")
	result := []byte("{")
	for _, v := range pairs {
		parts := strings.Split(v, "=")
		if parts[0] != "" {
			result = append(result, "\n  "+parts[0]+": '"+parts[1]+"',"...)
		}
	}
	result = result[:len(result)-1]
	result = append(result, "\n}"...)
	return string(result)
}

func makeProfiles(profiles []profile) func(string) string {
	db := make(map[string]profile)
	for _, v := range profiles {
		db[v.email] = v
	}
	profileMaker := func(email string) string {
		email = strings.Split(strings.Split(email, "&")[0], "=")[0]
		item, ok := db[email]
		var encodedProfile string
		if ok {
			encodedProfile = "email=" + item.email + "&uid=" + strconv.Itoa(int(item.uid)) + "&role=" + item.role
		}
		return encodedProfile
	}

	return profileMaker
}

func makeProfileCiphers(ps []profile) (func(string) []byte, func([]byte) string) {
	ciph := makeAES(randKey(aes.BlockSize))
	profileFor := makeProfiles(ps)
	encryptor := func(email string) []byte {
		return ecbEncrypt(pkcs7Pad([]byte(profileFor(email)), ciph.BlockSize()), ciph)
	}
	decryptor := func(cipherText []byte) string {
		return kvParse(string(pkcs7Unpad(ecbDecrypt(cipherText, ciph))))
	}

	return encryptor, decryptor
}

func makeRandomHeadPayloadEncryptionOracle(pl string, ciph cipher.Block) oracle {
	pt := make([]byte, mathrand.Intn(1000))
	rand.Read(pt)
	return func(in []byte) []byte {
		payload := base64Decode(pl)
		pt = append(pt, in...)
		pt = append(pt, payload...)
		pt = pkcs7Pad(pt, ciph.BlockSize())
		return ecbEncrypt(pt, ciph)
	}
}

func ecbDecrypt1by1RandHeader(encryptor oracle) []byte {
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

	isECB, _ := detectECB(encryptor(bytes.Repeat([]byte{'A'}, 3*blockLen)), blockLen)

	if !isECB {
		fmt.Print("no ecb detected\n")
		return nil
	}

	pt = []byte("")
	limit := len(encryptor([]byte{}))
	for i := 0; i < limit; i++ {
		craft := bytes.Repeat([]byte{'A'}, blockLen)
		craft = append(craft, pt...)
		craft = append(craft, '?')
		craft = craft[len(craft)-blockLen:]
		blocks := makeDictionary(pt, blockLen, encryptor)
		ct := encryptor(bytes.Repeat([]byte{'A'}, blockLen-len(pt)%blockLen-1))
		skip := i / blockLen * blockLen
		v := blocks[string(ct[skip:skip+blockLen])]
		pt = append(pt, v)
	}

	return pt
}
