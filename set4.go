package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"cryptopals/gosha1"
	"errors"
	"math/big"
	"strings"
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

func keyedSha1(key, msg []byte) []byte {
	h := gosha1.New()
	toHash := make([]byte, len(key)+len(msg))
	copy(toHash, key)
	copy(toHash[len(key):], msg)
	return h.Sum(toHash)
}

func checkKeyedSha1(key, msg, shasum []byte) bool {
	s := keyedSha1(key, msg)
	return bytes.Equal(s, shasum)
}

func sha1Padding(in []byte) []byte {
	bs := uint64(64)
	pad := make([]byte, bs)
	pad[0] = 0x80
	lenpadded := uint64(len(in))
	howmany := uint64(0)
	if lenpadded%bs < 56 {
		howmany = 56 - lenpadded%bs
	} else {
		howmany = bs + 56 - lenpadded%bs
	}
	pad = append(pad, bytes.Repeat([]byte{0}, int(howmany))...)
	lenpadded = uint64(len(pad))
	lenbits := len(in) << 3
	pad[lenpadded-8] = byte(lenbits >> 56)
	pad[lenpadded-7] = byte(lenbits >> 48)
	pad[lenpadded-6] = byte(lenbits >> 40)
	pad[lenpadded-5] = byte(lenbits >> 32)
	pad[lenpadded-4] = byte(lenbits >> 24)
	pad[lenpadded-3] = byte(lenbits >> 16)
	pad[lenpadded-2] = byte(lenbits >> 8)
	pad[lenpadded-1] = byte(lenbits)
	return pad
}
