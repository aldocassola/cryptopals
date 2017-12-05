package cryptopals

import (
	"bytes"
	"crypto/sha1"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
)

func bytesToBigInt(in []byte) *big.Int {
	return big.NewInt(int64(0)).SetBytes(in)
}

func bytesToBigIntMod(n *big.Int) *big.Int {
	r := bytesToBigInt(randKey(len(n.Bytes())))
	return r.Mod(r, n)
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

const (
	pubKeySent  = 1
	msgExchange = 2
)

type paramsPub struct {
	prime     *big.Int
	generator *big.Int
	pubKey    *big.Int
}

func (p *paramsPub) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, hexEncode(p.prime.Bytes()), hexEncode(p.generator.Bytes()), hexEncode(p.pubKey.Bytes()))
	return buf.Bytes(), nil
}

func (p *paramsPub) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var pstr, gstr, pubstr string
	_, err := fmt.Fscanln(b, &pstr, &gstr, &pubstr)
	p.prime.SetBytes(hexDecode(pstr))
	p.generator.SetBytes(hexDecode(gstr))
	p.pubKey.SetBytes(hexDecode(pubstr))
	return err
}

type pubOnly struct {
	pubKey *big.Int
}

func (p *pubOnly) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, hexEncode(p.pubKey.Bytes()))
	return buf.Bytes(), nil
}

func (p *pubOnly) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var pubstr string
	_, err := fmt.Fscanln(b, &pubstr)
	p.pubKey.SetBytes(hexDecode(pubstr))
	return err
}

type dhEchoData struct {
	bs   int
	iv   []byte
	data []byte
}

type connState struct {
	state   int
	params  *paramsPub
	privKey *big.Int
	pubKey  *pubOnly
	key     []byte
}

func (p *dhEchoData) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintln(&buf, p.bs, hexEncode(p.iv), hexEncode(p.data))
	return buf.Bytes(), nil
}

func (p *dhEchoData) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var bsstr, ivstr, datastr string
	_, err := fmt.Fscanln(b, &bsstr, &ivstr, &datastr)
	p.bs, _ = strconv.Atoi(bsstr)
	p.iv = hexDecode(ivstr)
	p.data = hexDecode(datastr)
	return err
}

func makeDHpublic(dhparams *paramsPub, priv *big.Int) *pubOnly {
	return &pubOnly{bigPowMod(dhparams.generator, priv, dhparams.prime)}
}

func dhKeyExchange(dhparams *paramsPub, pub *pubOnly, priv *big.Int) []byte {
	shared := bigPowMod(dhparams.pubKey, priv, dhparams.prime)
	priv = big.NewInt(int64(0))
	tmp := sha1.Sum(shared.Bytes())
	return tmp[:16]
}

func runDHEchoServer() {
	const bufSize = uint16(0xffff)
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 9001,
	}
	conn, err := net.ListenUDP("udp4", &listenAddr)
	if err != nil {
		log.Fatalf("Could not listen on udp port: %s", err.Error())
	}
	inbuf := make([]byte, bufSize)
	var buf bytes.Buffer
	hostStateMap := make(map[string]connState)
	enc, dec := gob.NewEncoder(&buf), gob.NewDecoder(&buf)
	for {
		recvLen, addr, err := conn.ReadFromUDP(inbuf)
		if err != nil {
			log.Printf("Could not receive from network: %s", err.Error())
		}
		remoteAddr := addr.String()
		buf.Write(inbuf[:recvLen])
		state, ok := hostStateMap[remoteAddr]
		if !ok {
			params := new(paramsPub)
			err := dec.Decode(params)
			if err != nil {
				log.Printf("Invalid parameters on first packet from: %s", addr.String())
				continue
			}
			myPriv := bytesToBigIntMod(params.prime)
			myPub := makeDHpublic(params, myPriv)
			client := new(connState)
			client.params = params
			client.privKey = myPriv
			client.pubKey = myPub
			buf.Reset()
			err = enc.Encode(client.pubKey)
			if err != nil {
				log.Printf("Error encoding public key for %s", addr.String())
				continue
			}
			_, err = conn.WriteTo(buf.Bytes(), addr)
			if err != nil {
				log.Printf("Error sending public key to %s", addr.String())
				continue
			}
			client.state = pubKeySent
			hostStateMap[remoteAddr] = *client
			continue
		}
		switch state.state {
		case paramsReceived:

		}
	}

}
