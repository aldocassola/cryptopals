package cryptopals

import (
	"bytes"
	"crypto/cipher"
)

func pkcs7Pad(in []byte, bs int) []byte {
	out := make([]byte, len(in), bs*(len(in)/bs+1))
	copy(out, in)
	remain := bs - len(in)%bs
	out = append(out, bytes.Repeat([]byte{byte(remain)}, remain)...)
	return out
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
