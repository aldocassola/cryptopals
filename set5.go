package cryptopals

import "math/big"

func bytesToBigInt(in []byte) *big.Int {
	return big.NewInt(int64(0)).SetBytes(in)
}

func hexStringToBigInt(hex string) *big.Int {
	return bytesToBigInt(hexDecode(hex))
}

func powMod(base, exp, mod uint64) uint64 {
	result := uint64(1)
	for exp != 0 {
		if exp%2 == 1 {
			result = (base * result) % mod
		}
		exp >>= 1
		base = (base * base) % mod
	}
	return result
}

func bigPowMod(base, exp, mod *big.Int) *big.Int {
	result := big.NewInt(int64(1))
	zero := big.NewInt(int64(0))
	one := big.NewInt(int64(1))
	two := big.NewInt(int64(2))
	for exp.Cmp(zero) == 0 {
		var mod2 big.Int
		if mod2.Mod(exp, two).Cmp(one) == 0 {
			result.Mul(result, base)
			result.Mod(result, mod)
		}
		exp.Div(exp, two)
		result.Mul(result, result)
		result.Mod(result, mod)
	}
	return result
}
