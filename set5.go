package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

func makeDHprivate(prime *big.Int) *big.Int {
	return bytesToBigIntMod(prime)
}

func bytesToBigInt(in []byte) *big.Int {
	incopy := make([]byte, len(in))
	copy(incopy, in)
	return big.NewInt(int64(0)).SetBytes(incopy)
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
	result := big.NewInt(1)
	zero := big.NewInt(0)
	one := big.NewInt(1)
	two := big.NewInt(2)
	base0 := bytesToBigInt(base.Bytes())
	exp0 := bytesToBigInt(exp.Bytes())

	for exp0.Cmp(zero) != 0 {
		var mod2 big.Int
		if mod2.Mod(exp0, two).Cmp(one) == 0 {
			result.Mul(result, base0)
			result.Mod(result, mod)
		}
		exp0.Div(exp0, two)
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
	if err != nil {
		log.Print(err.Error())
		return err
	}
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
	if err != nil {
		log.Print(err.Error())
		return err
	}
	p.pubKey = bytesToBigInt(hexDecode(pubstr))
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
	if err != nil {
		log.Print(err.Error())
		return err
	}
	p.bs, _ = strconv.Atoi(bsstr)
	p.iv = hexDecode(ivstr)
	p.data = hexDecode(datastr)
	return err
}

type connState struct {
	params *paramsPub
	pubKey *pubOnly
	ciph   cipher.Block
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

//RunDHEchoClient runs dhEcho client with given args
func RunDHEchoClient(hostname string, port int) {
	nistPstrs := strings.Fields(`ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff`)
	var nistPstr string
	for _, v := range nistPstrs {
		nistPstr += v
	}
	nistP := bytesToBigInt(hexDecode(nistPstr))
	nistG := bytesToBigInt(hexDecode("02"))
	dhEchoClient(hostname, port, nistG, nistP)
}

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
	_, err = receiveData(conn, theirPub)
	if err != nil {
		log.Fatal("Invalid remote public key")
	}
	key := dhKeyExchange(params, theirPub, myPriv)
	myPriv = nil
	var msg string
	ciph := makeAES(key)
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("> ")
		msg, err = reader.ReadString('\n')
		if err != nil {
			continue
		}
		data := new(dhEchoData)
		data.bs = ciph.BlockSize()
		data.iv = randKey(data.bs)
		data.data = cbcEncrypt(pkcs7Pad([]byte(msg), data.bs), data.iv, ciph)
		err = sendData(data, conn, nil)
		if err != nil {
			log.Fatal("Error sending encrypted message")
		}
		_, err = receiveData(conn, data)
		padded := cbcDecrypt(data.data, data.iv, ciph)
		unpadded, err := pkcs7Unpad(padded)
		if err != nil {
			log.Fatal("Padding error from server")
		}
		msg = string(unpadded)
		fmt.Printf("< %s", msg)
	}
	fmt.Printf("Exiting...\n")
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
		tmpbuf, addr, err := receiveBytes(conn)
		if err != nil {
			log.Print("Error receiving packet")
			continue
		}
		remoteAddr := addr.String()
		state, ok := hostStateMap[remoteAddr]
		if !ok {
			params := new(paramsPub)
			err = decodeData(tmpbuf, params)
			if err != nil {
				log.Printf("Invalid parameters on first packet from: %s", remoteAddr)
				continue
			}
			newClient := initClient(params)
			err = sendData(newClient.pubKey, conn, addr)
			if err != nil {
				log.Printf("Error sending public key to %s", remoteAddr)
				continue
			}
			hostStateMap[remoteAddr] = newClient
		} else {
			msg := new(dhEchoData)
			err = decodeData(tmpbuf, msg)
			if err != nil {
				log.Printf("Invalid data received from: %s", remoteAddr)
				continue
			}
			padded := cbcDecrypt(msg.data, msg.iv, state.ciph)
			pt, err := pkcs7Unpad(padded)
			if err != nil {
				log.Printf("Bad padding on message from: %s", remoteAddr)
				continue
			}
			msg.iv = randKey(msg.bs)
			ct := cbcEncrypt(pkcs7Pad(pt, msg.bs), msg.iv, state.ciph)
			msg.data = ct
			err = sendData(msg, conn, addr)
			if err != nil {
				log.Printf("Error encoding reply to %s", remoteAddr)
				continue
			}
		}
	}
}

func initClient(params *paramsPub) *connState {
	myPriv := makeDHprivate(params.prime)
	myPub := makeDHpublic(params, myPriv)
	client := new(connState)
	client.params = params
	client.pubKey = myPub
	sharedkey := dhKeyExchange(params, myPub, myPriv)
	myPriv = big.NewInt(int64(0))
	client.ciph = makeAES(sharedkey)
	return client
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

func receiveData(conn *net.UDPConn, data encoding.BinaryUnmarshaler) (*net.UDPAddr, error) {
	buf, addr, err := receiveBytes(conn)
	if err != nil {
		return nil, err
	}
	err = decodeData(buf, data)
	if err != nil {
		return nil, err
	}
	return addr, nil
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

func decodeData(inbuf []byte, data encoding.BinaryUnmarshaler) error {
	var buf bytes.Buffer
	buf.Write(inbuf)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(data)
	if err != nil {
		return err
	}
	return nil
}
