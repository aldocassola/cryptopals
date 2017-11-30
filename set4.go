package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
