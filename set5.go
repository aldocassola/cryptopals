package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"net"
	"strconv"
)

func makeDHprivate(prime *big.Int) *big.Int {
	return bytesToBigIntMod(prime)
}

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
	tmp := *base
	base0 := &tmp
	for exp.Cmp(zero) == 0 {
		var mod2 big.Int
		if mod2.Mod(exp, two).Cmp(one) == 0 {
			result.Mul(result, base0)
			result.Mod(result, mod)
		}
		exp.Div(exp, two)
		base0.Mul(base0, base0)
		base0.Mod(base0, mod)
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
	p.prime = bytesToBigInt(hexDecode(pstr))
	p.generator = bytesToBigInt(hexDecode(gstr))
	p.pubKey = bytesToBigInt(hexDecode(pubstr))
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
	p.pubKey = bytesToBigInt(hexDecode(pubstr))
	return err
}

type dhEchoData struct {
	bs   int
	iv   []byte
	data []byte
}

type connState struct {
	params *paramsPub
	pubKey *pubOnly
	ciph   cipher.Block
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
	tmp := sha1.Sum(shared.Bytes())
	return tmp[:16]
}

const bufSize = uint16(0xffff)

func dhEchoClient(hostname string, port int, g *big.Int, p *big.Int) {
	srvIPs, err := net.LookupHost(hostname)
	if err != nil {
		log.Fatal("Host %s not found", hostname)
	}
	serverAddr := net.UDPAddr{
		IP:   net.ParseIP(srvIPs[0]),
		Port: port,
	}
	conn, err := net.DialUDP("udp4", nil, &serverAddr)
	if err != nil {
		log.Fatal("Could not contact server %s", hostname)
	}
	params := new(paramsPub)
	params.generator = g
	params.prime = p
	myPriv := makeDHprivate(p)
	myPub := makeDHpublic(params, myPriv).pubKey
	params.pubKey = myPub
	err = sendData(params, conn, nil)
	if err != nil {
		log.Fatal("Exiting")
	}
	theirPub := new(pubOnly)
	tmp, _, err := receiveData(conn, theirPub)
	if err != nil {
		log.Fatal("Invalid remote public key")
	}
	theirPub = tmp.(*pubOnly)
	key := dhKeyExchange(params, theirPub, myPriv)
	myPriv = nil
	var msg string
	ciph := makeAES(key)
	for {
		fmt.Printf("> ")
		fmt.Scanln("%s", &msg)
		data := new(dhEchoData)
		data.bs = ciph.BlockSize()
		data.iv = randKey(data.bs)
		err = sendData(data, conn, nil)
		if err != nil {
			log.Fatal("Error sending encrypted message")
		}
		tmp, _, err = receiveData(conn, data)
		data = tmp.(*dhEchoData)
		msg = string(cbcDecrypt(data.data, data.iv, ciph))
		fmt.Printf("< %s", msg)
	}
}

func runDHEchoServer(port int) {
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
	conn, err := net.ListenUDP("udp4", &listenAddr)
	defer conn.Close()
	if err != nil {
		log.Fatalf("Could not listen on udp port: %s", err.Error())
	}
	hostStateMap := make(map[string]*connState)
	for {
		params := new(paramsPub)
		tmp, addr, err := receiveData(conn, params)
		if err != nil {
			log.Print("Invalid parameters received")
			continue
		}
		params = tmp.(*paramsPub)
		remoteAddr := addr.String()
		state, ok := hostStateMap[remoteAddr]
		if !ok {
			newClient, err := initClient(params)
			if err != nil {
				log.Printf("Invalid parameters on first packet from: %s", addr.String())
				continue
			}
			hostStateMap[remoteAddr] = newClient
		} else {
			msg := new(dhEchoData)
			tmp, addr, _ := receiveData(conn, msg)
			msg = tmp.(*dhEchoData)
			pt := cbcDecrypt(msg.data, msg.iv, state.ciph)
			msg.iv = randKey(msg.bs)
			msg.data = cbcEncrypt(pt, msg.iv, state.ciph)
			err = sendData(msg, conn, addr)
			if err != nil {
				log.Printf("Error encoding reply to %s", addr.String())
				continue
			}
		}
	}
}

func initClient(params *paramsPub) (*connState, error) {
	myPriv := makeDHprivate(params.prime)
	myPub := makeDHpublic(params, myPriv)
	client := new(connState)
	client.params = params
	client.pubKey = myPub
	sharedkey := dhKeyExchange(params, myPub, myPriv)
	myPriv = big.NewInt(int64(0))
	client.ciph = makeAES(sharedkey)
	return client, nil
}

func sendData(data encoding.BinaryMarshaler, conn *net.UDPConn, addr *net.UDPAddr) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		log.Printf("Error encoding public key for %s", addr.String())
		return err
	}
	if addr != nil {
		_, err = conn.WriteTo(buf.Bytes(), addr)
	} else {
		_, err = conn.Write(buf.Bytes())
	}
	if err != nil {
		log.Printf("Error sending data to %s: %s", addr.String(), err.Error())
		return err
	}
	return nil
}

func receiveBytes(conn *net.UDPConn) ([]byte, *net.UDPAddr, error) {
	inbuf := make([]byte, bufSize)
	recvLen, addr, err := conn.ReadFromUDP(inbuf)
	if err != nil {
		log.Printf("Could not receive from network: %s", err.Error())
		return nil, nil, err
	}
	return inbuf[:recvLen], addr, err
}

func receiveData(conn *net.UDPConn, data encoding.BinaryUnmarshaler) (encoding.BinaryUnmarshaler, *net.UDPAddr, error) {
	inbuf, addr, err := receiveBytes(conn)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	buf.Write(inbuf)
	dec := gob.NewDecoder(&buf)
	err = dec.Decode(data)
	if err != nil {
		return nil, nil, err
	}
	return data, addr, nil
}
