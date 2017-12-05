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
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 9001,
	}
	for {
		conn, err := net.ListenUDP("udp4", &listenAddr)
		if err != nil {
			panic("Could not listen on udp port: " + err.Error())
		}
		go func(c net.Conn) {
			defer c.Close()
			enc, dec := gob.NewEncoder(c), gob.NewDecoder(c)
			var p1 paramsPub
			err := dec.Decode(&p1)
			if err != nil {
				log.Printf("Error decoding parameters")
				return
			}
			myPriv := bytesToBigIntMod(p1.prime)
			myPub := makeDHpublic(&p1, myPriv)
			err = enc.Encode(myPub)
			if err != nil {
				log.Printf("Error encoding public key")
				return
			}
			k := dhKeyExchange(&p1, myPub, myPriv)
			ciph := makeAES(k)
			for {
				var msg dhEchoData
				err = dec.Decode(&msg)
				if err != nil {
					log.Printf("Error decoding message")
					return
				}
				pt := cbcDecrypt(msg.data, msg.iv, ciph)
				myiv := randKey(msg.bs)
				ct := cbcEncrypt(pt, myiv, ciph)
				reply := dhEchoData{
					bs:   msg.bs,
					iv:   myiv,
					data: ct,
				}
				err = enc.Encode(reply)
				if err != nil {
					fmt.Printf("Error encoding message")
					return
				}
			}
		}(conn)

	}
}
