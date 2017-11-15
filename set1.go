package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

func hexToBase64(in string) string {
	hs, error := hex.DecodeString(in)

	if error != nil {
		_ = fmt.Errorf("Invalid hex string: %s", in)
		return ""
	}

	return base64.StdEncoding.EncodeToString(hs)
}

func xor(s, t []byte) []byte {

	if len(s) > len(t) {
		s = s[:len(t)]
	}

	res := make([]byte, len(s))

	for i := range s {
		res[i] = s[i] ^ t[i]
	}

	return res

}
