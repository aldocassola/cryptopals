package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding"
	"encoding/gob"
	"fmt"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
)

func getNistP() *big.Int {
	const nistPstrs = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
	e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
	3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
	6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
	24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
	c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
	bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
	fffffffffffff`
	var nistPstr string
	for _, v := range strings.Fields(nistPstrs) {
		nistPstr += v
	}
	return newBigIntFromBytes(hexDecode(nistPstr))
}

func makeDHprivate(prime *big.Int) *big.Int {
	return newRandBigIntMod(prime)
}

func newBigIntFromBytes(in []byte) *big.Int {
	incopy := make([]byte, len(in))
	copy(incopy, in)
	return big.NewInt(0).SetBytes(incopy)
}

func newRandBigIntMod(n *big.Int) *big.Int {
	r := newBigIntFromBytes(randKey(len(n.Bytes())))
	return r.Mod(r, n)
}

func hexStringToBigInt(hex string) *big.Int {
	return newBigIntFromBytes(hexDecode(hex))
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
	base0 := big.NewInt(0).Set(base)
	exp0 := big.NewInt(0).Set(exp)

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
	primeBytes := p.prime.Bytes()
	genBytes := p.generator.Bytes()
	pubBytes := p.pubKey.Bytes()
	fmt.Fprintf(&buf, "%q %q %q\n", hexEncode(primeBytes), hexEncode(genBytes), hexEncode(pubBytes))
	return buf.Bytes(), nil
}

func (p *paramsPub) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var pstr, gstr, pubstr string
	_, err := fmt.Fscanf(b, "%q %q %q", &pstr, &gstr, &pubstr)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	p.prime = newBigIntFromBytes(hexDecode(pstr))
	p.generator = newBigIntFromBytes(hexDecode(gstr))
	p.pubKey = newBigIntFromBytes(hexDecode(pubstr))
	return err
}

type pubOnly struct {
	pubKey *big.Int
}

func (p *pubOnly) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%q\n", hexEncode(p.pubKey.Bytes()))
	return buf.Bytes(), nil
}

func (p *pubOnly) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var pubstr string
	_, err := fmt.Fscanf(b, "%q\n", &pubstr)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	p.pubKey = newBigIntFromBytes(hexDecode(pubstr))
	return err
}

type dhEchoData struct {
	bs   int
	iv   []byte
	data []byte
}

func (p *dhEchoData) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%d %q %q\n", p.bs, hexEncode(p.iv), hexEncode(p.data))
	return buf.Bytes(), nil
}

func (p *dhEchoData) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var bsstr, ivstr, datastr string
	_, err := fmt.Fscanf(b, "%s %q %q\n", &bsstr, &ivstr, &datastr)
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

func makeDHpublic(generator, prime, priv *big.Int) *big.Int {
	return bigPowMod(generator, priv, prime)
}

func dhKeyExchange(prime, pub, priv *big.Int) []byte {
	shared := bigPowMod(pub, priv, prime)
	tmp := sha1.Sum(shared.Bytes())
	priv.SetInt64(0)
	return tmp[:]
}

const bufSize = uint16(0xffff)

func dhEchoTestClient(hostname string, port int, g, p *big.Int, numTests int, t *testing.T) {
	conn, err := dhEchoConnect(hostname, port)
	defer conn.Close()
	params, myPriv := makeParamsPub(g, p)
	err = sendData(params, conn, nil)
	if err != nil {
		t.Error("Could not send data to server")
	}
	theirPub := new(pubOnly)
	_, err = receiveData(conn, theirPub)
	if err != nil {
		t.Error("Invalid remote public key")
	}
	ciph, err := initDHCipher(aes.NewCipher, params.prime, theirPub.pubKey, myPriv, aes.BlockSize)
	if err != nil {
		t.Error("Could not generate key")
	}
	for i := 0; i < numTests; i++ {
		msgtxt := base64Encode(randKey(mathrand.Intn(100)))
		reply, err := sendStringGetReply(msgtxt, conn, ciph)
		if err != nil {
			t.Error("Could not get reply")
		}
		if strings.Compare(msgtxt, reply) != 0 {
			t.Error("strings differ")
			break
		}
	}
}

//RunDHEchoClient runs dhEcho client with given args
func RunDHEchoClient(hostname string, port int) {
	nistP := getNistP()
	nistG := newBigIntFromBytes(hexDecode("02"))
	dhEchoClient(hostname, port, nistG, nistP)
}

func dhEchoClient(hostname string, port int, g *big.Int, p *big.Int) {
	conn, err := dhEchoConnect(hostname, port)
	defer conn.Close()
	params, myPriv := makeParamsPub(g, p)
	err = sendData(params, conn, nil)
	if err != nil {
		log.Fatal("Exiting")
	}
	theirPub := new(pubOnly)
	_, err = receiveData(conn, theirPub)
	if err != nil {
		log.Fatal("Invalid remote public key")
	}
	ciph, err := initDHCipher(aes.NewCipher, params.prime, theirPub.pubKey, myPriv, aes.BlockSize)
	if err != nil {
		log.Fatal("Coiuld not generate key")
	}
	var msg string
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("> ")
		msg, err = reader.ReadString('\n')
		if err != nil {
			break
		}
		reply, err := sendStringGetReply(msg, conn, ciph)
		if err == nil {
			log.Fatal("Error sending encrypted message")
		}
		fmt.Printf("< %s", reply)
	}
	fmt.Printf("Exiting...\n")
}

func initDHCipher(
	genCipher func([]byte) (cipher.Block, error),
	prime, remotePub, myPriv *big.Int, byteCount int) (cipher.Block, error) {
	key := dhKeyExchange(prime, remotePub, myPriv)
	ciph, err := genCipher(key[:byteCount])
	return ciph, err
}

func dhEchoConnect(hostname string, port int) (*net.UDPConn, error) {
	srvIPs, err := net.LookupHost(hostname)
	if err != nil {
		log.Fatalf("Host %s not found", hostname)
	}
	var conn *net.UDPConn
	for i := 0; i < len(srvIPs); i++ {
		serverAddr := net.UDPAddr{
			IP:   net.ParseIP(srvIPs[i]),
			Port: port,
		}
		conn, err = net.DialUDP("udp4", nil, &serverAddr)
		if err != nil {
			continue
		}
		return conn, err
	}
	return nil, err
}

func makeParamsPub(g, p *big.Int) (*paramsPub, *big.Int) {
	params := new(paramsPub)
	params.generator = g
	params.prime = p
	myPriv := makeDHprivate(p)
	myPub := makeDHpublic(params.generator, params.prime, myPriv)
	params.pubKey = myPub
	return params, myPriv
}

func sendStringGetReply(msg string, conn *net.UDPConn, ciph cipher.Block) (string, error) {
	data := new(dhEchoData)
	data.bs = ciph.BlockSize()
	data.iv = randKey(data.bs)
	padded := pkcs7Pad([]byte(msg), data.bs)
	data.data = cbcEncrypt(padded, data.iv, ciph)
	err := sendData(data, conn, nil)
	if err != nil {
		return "", err
	}
	_, err = receiveData(conn, data)
	padded = cbcDecrypt(data.data, data.iv, ciph)
	unpadded, err := pkcs7Unpad(padded)
	if err != nil {
		log.Fatal("decryption error from server")
	}
	return string(unpadded), nil
}

func receiveMsgEchoReply(tmpbuf []byte, conn *net.UDPConn, addr *net.UDPAddr, cli *connState) error {
	msg := new(dhEchoData)
	err := decodeData(tmpbuf, msg)
	if err != nil {
		return err
	}
	padded := cbcDecrypt(msg.data, msg.iv, cli.ciph)
	pt, err := pkcs7Unpad(padded)
	if err != nil {
		return err
	}
	msg.iv = randKey(msg.bs)
	ct := cbcEncrypt(pkcs7Pad(pt, msg.bs), msg.iv, cli.ciph)
	msg.data = ct
	err = sendData(msg, conn, addr)
	if err != nil {
		return err
	}
	return nil
}

func udpListen(port int) (*net.UDPConn, error) {
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
	conn, err := net.ListenUDP("udp4", &listenAddr)
	return conn, err
}

func runDHEchoServer(port int) {
	conn, err := udpListen(port)
	if err != nil {
		log.Fatalf("Could not listen on port %d", port)
	}
	defer conn.Close()
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
				log.Printf("Invalid data on first packet from: %s", remoteAddr)
				continue
			}
			newClient, err := initClient(params, aes.BlockSize)
			if err != nil {
				log.Printf("Invalid parameters on first packet from: %s", remoteAddr)
				continue
			}
			err = sendData(newClient.pubKey, conn, addr)
			if err != nil {
				log.Printf("Error sending public key to %s", remoteAddr)
				continue
			}
			hostStateMap[remoteAddr] = newClient
		} else {
			err = receiveMsgEchoReply(tmpbuf, conn, addr, state) //
			if err != nil {
				log.Printf("Could not receive message from: %s", remoteAddr)
				delete(hostStateMap, remoteAddr)
				continue
			}
		}
	}
}

func initClient(params *paramsPub, keySize int) (*connState, error) {
	myPriv := makeDHprivate(params.prime)
	myPub := makeDHpublic(params.generator, params.prime, myPriv)
	pubObj := new(pubOnly)
	pubObj.pubKey = myPub
	client := new(connState)
	client.params = params
	client.pubKey = pubObj
	var err error
	client.ciph, err = initDHCipher(aes.NewCipher, params.prime, params.pubKey, myPriv, keySize)
	if err != nil {
		return nil, err
	}
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

func runParameterInjector(server string, serverPort, listenport int) {
	cliconn, err := udpListen(listenport)
	if err != nil {
		log.Fatalf("Could not listen on port %d", listenport)
	}
	shared := sha1.Sum(big.NewInt(0).Bytes())
	ciph := makeAES(shared[:aes.BlockSize])
	servconn, err := dhEchoConnect(server, serverPort)
	if err != nil {
		log.Fatal("Could not open connection to server")
	}
	defer servconn.Close()
	clientMap := make(map[string]*connState)
	for {
		buf, cliaddr, err := receiveBytes(cliconn)
		if err != nil {
			log.Print("Could not read from socket")
			continue
		}
		clientAddress := cliaddr.String()
		_, ok := clientMap[clientAddress]
		if !ok {
			params := new(paramsPub)
			err = decodeData(buf, params)
			if err != nil {
				log.Print("Invalid params")
				continue
			}
			params.pubKey = big.NewInt(0).Set(params.prime)
			newcli, _ := initClient(params, aes.BlockSize)
			err = sendData(params, servconn, nil)
			if err != nil {
				log.Print("could not send parameters to server")
				continue
			}
			clientMap[clientAddress] = newcli
			servPub := new(pubOnly)
			_, err := receiveData(servconn, servPub)
			if err != nil {
				log.Print("Could not receive pubkey from server")
				delete(clientMap, clientAddress)
				continue
			}
			servPub.pubKey = big.NewInt(0).Set(params.prime)
			err = sendData(servPub, cliconn, cliaddr)
		} else {
			msg := new(dhEchoData)
			err := decodeData(buf, msg)
			padded := cbcDecrypt(msg.data, msg.iv, ciph)
			pt, err := pkcs7Unpad(padded)
			if err != nil {
				log.Printf("decryption error from %s", clientAddress)
				continue
			}
			log.Printf("c->s: %s", string(pt))
			err = sendData(msg, servconn, nil)
			if err != nil {
				log.Print("Could not relay message to server")
				continue
			}
			_, err = receiveData(servconn, msg)
			if err != nil {
				log.Print("Could not receive reply from server")
				continue
			}
			padded = cbcDecrypt(msg.data, msg.iv, ciph)
			pt, err = pkcs7Unpad(padded)
			log.Printf("c<-s: %s", string(pt))
			err = sendData(msg, cliconn, cliaddr)
		}
	}
}

type dhParameters struct {
	prime     *big.Int
	generator *big.Int
}

func (p *dhParameters) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%q %q\n", hexEncode(p.prime.Bytes()), hexEncode(p.generator.Bytes()))
	return buf.Bytes(), nil
}

func (p *dhParameters) UnmarshalBinary(data []byte) error {
	b := bytes.NewBuffer(data)
	var pstr, gstr string
	_, err := fmt.Fscanf(b, "%q %q\n", &pstr, &gstr)
	if err != nil {
		log.Print(err.Error())
		return err
	}
	p.prime = newBigIntFromBytes(hexDecode(pstr))
	p.generator = newBigIntFromBytes(hexDecode(gstr))
	return err
}

func makeParams(p, g *big.Int) *dhParameters {
	result := new(dhParameters)
	result.generator = big.NewInt(0).Set(g)
	result.prime = big.NewInt(0).Set(p)
	return result
}

type dhACK struct{}

func (a *dhACK) MarshalBinary() ([]byte, error) {
	result := make([]byte, 1)
	result[0] = 0xAC
	return result, nil
}

func (a *dhACK) UnmarshalBinary(data []byte) error {
	if len(data) != 1 || data[0] != 0xAC {
		return newError("Invalid ACK")
	}
	return nil
}

func runDHNegoEchoServer(listenPort int) {
	conn, err := udpListen(listenPort)
	if err != nil {
		log.Fatalf("Could not listen on port %d", listenPort)
	}
	cliMap := make(map[string]*connState)
	for {
		buf, addr, err := receiveBytes(conn)
		if err != nil {
			log.Printf("Could not receive bytes")
			continue
		}
		remoteAddr := addr.String()
		cli, ok := cliMap[remoteAddr]
		if !ok {
			negoParams := new(dhParameters)
			err = decodeData(buf, negoParams)
			if err != nil {
				log.Printf("Could not decode data from %s", remoteAddr)
				continue
			}
			ack := new(dhACK)
			err = sendData(ack, conn, addr)
			if err != nil {
				log.Printf("Could not send data to: %s", remoteAddr)
				continue
			}
			cliParams := new(paramsPub)
			cliParams.generator = negoParams.generator
			cliParams.prime = negoParams.prime
			cliParams.pubKey = nil
			newcli := new(connState)
			newcli.params = cliParams
			newcli.ciph = nil
			newcli.pubKey = nil
			cliMap[remoteAddr] = newcli
		} else if cli.ciph == nil { //if no shared key, receive public and send own public
			remotePub := new(pubOnly)
			err = decodeData(buf, remotePub)
			if err != nil {
				log.Printf("Received invalid public key from %s", remoteAddr)
				delete(cliMap, remoteAddr)
				continue
			}
			cli.params.pubKey = remotePub.pubKey
			newcli, err := initClient(cli.params, aes.BlockSize)
			if err != nil {
				log.Printf("Could not update client info with remote public key from %s", remoteAddr)
				delete(cliMap, remoteAddr)
				continue
			}
			cli = newcli
			err = sendData(cli.pubKey, conn, addr)
			if err != nil {
				log.Printf("Could not send public key to %s", remoteAddr)
				delete(cliMap, remoteAddr)
				continue
			}
			cliMap[remoteAddr] = newcli
		} else { //receive message
			err = receiveMsgEchoReply(buf, conn, addr, cli) //
			if err != nil {
				log.Printf("Could not receive message from: %s", remoteAddr)
				delete(cliMap, remoteAddr)
				continue
			}
		}
	}
}

func dhNegoEchoTestClient(hostname string, port int, g, p *big.Int, numTests int, t *testing.T) {
	conn, err := dhEchoConnect(hostname, port)
	defer conn.Close()
	params := new(dhParameters)
	params.generator = g
	params.prime = p
	myPriv := makeDHprivate(p)
	err = sendData(params, conn, nil)
	if err != nil {
		t.Error("Could not send data to server")
		return
	}
	ackData := new(dhACK)
	_, err = receiveData(conn, ackData)
	if err != nil {
		t.Error("Did not get ACK")
		return
	}
	pubData := new(pubOnly)
	pubData.pubKey = makeDHpublic(params.generator, params.prime, myPriv)
	err = sendData(pubData, conn, nil)
	if err != nil {
		t.Error("Could not send pubkey data")
		return
	}
	theirPub := new(pubOnly)
	_, err = receiveData(conn, theirPub)
	if err != nil {
		t.Error("Invalid remote public key")
		return
	}
	ciph, err := initDHCipher(aes.NewCipher, params.prime, theirPub.pubKey, myPriv, aes.BlockSize)
	if err != nil {
		t.Error("Could not generate key")
		return
	}
	for i := 0; i < numTests; i++ {
		msgtxt := base64Encode(randKey(mathrand.Intn(100)))
		t.Logf("sending: %s", msgtxt)
		reply, err := sendStringGetReply(msgtxt, conn, ciph)
		t.Logf("received: %s", reply)
		if err != nil {
			t.Error("Could not get reply")
			break
		}
		if strings.Compare(msgtxt, reply) != 0 {
			t.Error("strings differ")
			break
		}
	}
}

//runDHNegoParameterInjector injects a value given by ginject as follows:
//ginject = 0 injects p
//ginject = 1 injects 1
//ginject = -1 injects p-1
func runDHNegoParameterInjector(server string, serverPort, listenPort int, ginject *big.Int) {
	//my private key = 2
	t := big.NewInt(int64(2))
	cliconn, err := udpListen(listenPort)
	if err != nil {
		log.Fatalf("Could not listen on port %d", listenPort)
	}
	servconn, err := dhEchoConnect(server, serverPort)
	if err != nil {
		log.Fatal("Could not open connection to server")
	}
	defer servconn.Close()
	clientMap := make(map[string]*connState)
	for {
		buf, cliaddr, err := receiveBytes(cliconn)
		if err != nil {
			log.Println("Could not read from socket")
			continue
		}
		clientAddress := cliaddr.String()
		cli, ok := clientMap[clientAddress]
		if !ok {
			params := new(dhParameters)
			err = decodeData(buf, params)
			if err != nil {
				log.Println("Invalid params")
				continue
			}
			params.generator.Add(params.prime, ginject).Mod(params.generator, params.prime)
			err = sendData(params, servconn, nil)
			if err != nil {
				log.Println("could not send parameters to server")
				continue
			}
			newcli := new(connState)
			newcli.ciph = nil
			newcli.pubKey = nil
			newcli.params = new(paramsPub)
			newcli.params.generator = params.generator
			newcli.params.prime = params.prime
			clientMap[clientAddress] = newcli
			servAck := new(dhACK)

			//get ack
			_, err := receiveData(servconn, servAck)
			if err != nil {
				log.Println("Could not receive ACK from server")
				delete(clientMap, clientAddress)
				continue
			}
			err = sendData(servAck, cliconn, cliaddr)
			if err != nil {
				log.Println("Could not send ACK to client")
				delete(clientMap, clientAddress)
				continue
			}

			//if g = 1 or g = p,  we know what B's pubkey will be
			//g = 1 => B = 1 => k_AB = 1 = k_BA (for any t)
			//g = p => B = 0 => k_AB = 0 = k_BA (for any t)

			//if g = p-1:
			//g = p-1 => B could be p-1 (b odd) or 1 (b even)
			//if we set t = 2
			//k_AB = (p-1)^(2a), k_BA = (p-1)^(2b)
		} else if cli.ciph == nil {
			clipub := new(pubOnly)
			err := decodeData(buf, clipub)
			if err != nil {
				log.Println("Invalid public key from client")
				delete(clientMap, clientAddress)
				continue
			}
			cli.params.pubKey = clipub.pubKey

			//send g'^t to both parties
			pubk := new(pubOnly)
			pubk.pubKey = bigPowMod(cli.params.generator, t, cli.params.prime)
			err = sendData(pubk, servconn, nil)
			if err != nil {
				log.Println("Could not send our pubkey to server")
				delete(clientMap, clientAddress)
				continue
			}

			// get server public key
			servpub := new(pubOnly)
			_, err = receiveData(servconn, servpub)
			if err != nil {
				log.Println("Could not receive pubkey from server")
				delete(clientMap, clientAddress)
				continue
			}
			cli.pubKey = pubk
			err = sendData(pubk, cliconn, cliaddr)
			if err != nil {
				log.Println("Could not send our pubkey to client")
				delete(clientMap, clientAddress)
				continue
			}

			//TODO: setup the cipher
			var shared int64
			if ginject.Cmp(big.NewInt(int64(0))) == 0 { // K = 0
				shared = 0
			} else { // K = 1
				shared = 1
			}
			key := sha1.Sum(big.NewInt(shared).Bytes())
			cli.ciph, err = aes.NewCipher(key[:aes.BlockSize])
			if err != nil {
				log.Println("Could not create shared cipher")
				delete(clientMap, clientAddress)
				continue
			}

		} else {
			msg := new(dhEchoData)
			err := decodeData(buf, msg)
			padded := cbcDecrypt(msg.data, msg.iv, cli.ciph)
			pt, err := pkcs7Unpad(padded)
			if err != nil {
				log.Printf("decryption error from %s", clientAddress)
				continue
			}
			log.Printf("c->s: %s", string(pt))
			err = sendData(msg, servconn, nil)
			if err != nil {
				log.Print("Could not relay message to server")
				continue
			}
			_, err = receiveData(servconn, msg)
			if err != nil {
				log.Print("Could not receive reply from server")
				continue
			}
			padded = cbcDecrypt(msg.data, msg.iv, cli.ciph)
			pt, err = pkcs7Unpad(padded)
			log.Printf("c<-s: %s", string(pt))
			err = sendData(msg, cliconn, cliaddr)
		}
	}
}
