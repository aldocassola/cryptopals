package cryptopals

import "math/big"
import "net"

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

//packet types
const (
	_paramsPub  = 0
	_pubOnly    = 1
	_dhEchoData = 2
)

type dhEchoHeader struct {
	packetType int
	payloadLen int
}

type paramsPub struct {
	primeLen  int
	genLen    int
	pubLen    int
	prime     []byte
	generator []byte
	pubKey    []byte
}

type pubOnly struct {
	pubLen int
	pubKey []byte
}

type dhEchoData struct {
	bs   int
	iv   []byte
	data []byte
}

func runDHEchoServer() {
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 9001,
	}
	addr, err := net.ListenUDP("udp", &listenAddr)
	if err != nil {
		panic("Could not listen on udp port")
	}
	for {
		var header dhEchoHeader
		addr.Read(&header)
	}
}
