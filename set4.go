package cryptopals

import (
	"bytes"
	"crypto/cipher"
)

func makeEditCTR(nonce, ctrStart uint64) func(ct []byte, key []byte, offset uint64, newData []byte) []byte {
	n := nonce
	ctr := ctrStart
	return func(ct, ctrKey []byte, offset uint64, newText []byte) []byte {
		if offset+uint64(len(newText)) > uint64(len(ct)) {
			toAppend := offset + uint64(len(newText)) - uint64(len(ct))
			ct = append(ct, bytes.Repeat([]byte{0}, int(toAppend))...)
		}
		ciph := makeAES(ctrKey)
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

func recoverCTRPlaintext(ct, key []byte, nonce, ctrStart uint64) []byte {
	return nil
}
