package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"hash"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"
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
	return hexStringToBigInt(nistPstr)
}

func makeDHprivate(prime *big.Int) *big.Int {
	return newRandBigIntMod(prime)
}

func newBigIntFromBytes(in []byte) *big.Int {
	incopy := make([]byte, len(in))
	copy(incopy, in)
	return new(big.Int).SetBytes(incopy)
}

func newRandBigIntMod(n *big.Int) *big.Int {
	r, err := rand.Int(rand.Reader, n)
	if err != nil {
		panic("generating random")
	}
	return r
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
	zero := new(big.Int)
	one := big.NewInt(1)
	base0 := new(big.Int).Set(base)
	exp0 := new(big.Int).Set(exp)

	for exp0.Cmp(zero) != 0 {
		mod2 := new(big.Int).And(exp0, one)
		if mod2.Cmp(one) == 0 {
			result.Mul(result, base0).Mod(result, mod)
		}
		exp0.Rsh(exp0, 1)
		base0.Mul(base0, base0).Mod(base0, mod)
	}
	return result
}

type paramsPub struct {
	Prime     *big.Int
	Generator *big.Int
	PubKey    *big.Int
}

type pubOnly struct {
	PubKey *big.Int
}

type dhEchoData struct {
	Bs   int
	Iv   []byte
	Data []byte
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

func makeDHEchoTestClient(g, p *big.Int, numTests int, t *testing.T) func(*net.UDPConn) {
	return func(conn *net.UDPConn) {
		defer conn.Close()
		params, myPriv := makeParamsPub(g, p)
		err := sendData(params, conn, nil)
		if err != nil {
			t.Error("Could not send data to server")
		}
		theirPub := new(pubOnly)
		_, err = receiveData(conn, theirPub)
		if err != nil {
			t.Error("Invalid remote public key")
		}
		ciph, err := initDHCipher(aes.NewCipher, params.Prime, theirPub.PubKey, myPriv, aes.BlockSize)
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
}

//RunDHEchoClient runs dhEcho client with given args
func RunDHEchoClient(hostname string, port int) {
	nistP := getNistP()
	nistG := big.NewInt(2)
	cb := dhEchoClient(nistG, nistP)
	udpClient(hostname, port, cb)
}

func dhEchoClient(g *big.Int, p *big.Int) func(*net.UDPConn) {
	return func(conn *net.UDPConn) {
		defer conn.Close()
		params, myPriv := makeParamsPub(g, p)
		err := sendData(params, conn, nil)
		if err != nil {
			log.Fatal("Exiting")
		}
		theirPub := new(pubOnly)
		_, err = receiveData(conn, theirPub)
		if err != nil {
			log.Fatal("Invalid remote public key")
		}
		ciph, err := initDHCipher(aes.NewCipher, params.Prime, theirPub.PubKey, myPriv, aes.BlockSize)
		if err != nil {
			log.Fatal("Could not generate key")
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
}

func initDHCipher(
	genCipher func([]byte) (cipher.Block, error),
	prime, remotePub, myPriv *big.Int, byteCount int) (cipher.Block, error) {
	key := dhKeyExchange(prime, remotePub, myPriv)
	ciph, err := genCipher(key[:byteCount])
	return ciph, err
}

func udpClient(hostname string, port int, clientCb func(*net.UDPConn)) {
	//wait to make sure server has started
	time.Sleep(50 * time.Millisecond)
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
		clientCb(conn)
	}
}

func makeParamsPub(g, p *big.Int) (*paramsPub, *big.Int) {
	params := new(paramsPub)
	params.Generator = g
	params.Prime = p
	myPriv := makeDHprivate(p)
	myPub := makeDHpublic(params.Generator, params.Prime, myPriv)
	params.PubKey = myPub
	return params, myPriv
}

func sendStringGetReply(msg string, conn *net.UDPConn, ciph cipher.Block) (string, error) {
	data := new(dhEchoData)
	data.Bs = ciph.BlockSize()
	data.Iv = randKey(data.Bs)
	padded := pkcs7Pad([]byte(msg), data.Bs)
	data.Data = cbcEncrypt(padded, data.Iv, ciph)
	err := sendData(data, conn, nil)
	if err != nil {
		return "", err
	}
	_, err = receiveData(conn, data)
	padded = cbcDecrypt(data.Data, data.Iv, ciph)
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
	padded := cbcDecrypt(msg.Data, msg.Iv, cli.ciph)
	pt, err := pkcs7Unpad(padded)
	if err != nil {
		return err
	}
	msg.Iv = randKey(msg.Bs)
	ct := cbcEncrypt(pkcs7Pad(pt, msg.Bs), msg.Iv, cli.ciph)
	msg.Data = ct
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

func udpServer(port int, server func(conn *net.UDPConn)) {
	conn, err := udpListen(port)
	if err != nil {
		log.Fatalf("Could not listen on port %d", port)
	}
	defer conn.Close()

	server(conn)
}

func makeDHEchoServer() func(*net.UDPConn) {
	hostStateMap := make(map[string]*connState)
	return func(conn *net.UDPConn) {
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
}

func initClient(params *paramsPub, keySize int) (*connState, error) {
	myPriv := makeDHprivate(params.Prime)
	myPub := makeDHpublic(params.Generator, params.Prime, myPriv)
	pubObj := new(pubOnly)
	pubObj.PubKey = myPub
	client := new(connState)
	client.params = params
	client.pubKey = pubObj
	var err error
	client.ciph, err = initDHCipher(aes.NewCipher, params.Prime, params.PubKey, myPriv, keySize)
	if err != nil {
		return nil, err
	}
	return client, nil
}

func sendData(data interface{}, conn *net.UDPConn, addr *net.UDPAddr) error {
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

func receiveData(conn *net.UDPConn, data interface{}) (*net.UDPAddr, error) {
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

func decodeData(inbuf []byte, data interface{}) error {
	var buf bytes.Buffer
	buf.Write(inbuf)
	dec := gob.NewDecoder(&buf)
	err := dec.Decode(data)
	if err != nil {
		return err
	}
	return nil
}

func runParameterInjector(server string, serverPort, listenport int, t *testing.T) {
	cliconn, err := udpListen(listenport)
	if err != nil {
		log.Fatalf("Could not listen on port %d", listenport)
	}
	shared := sha1.Sum(new(big.Int).Bytes())
	ciph := makeAES(shared[:aes.BlockSize])
	clientMap := make(map[string]*connState)

	udpClient(server, serverPort, func(servconn *net.UDPConn) {
		defer servconn.Close()

		for {
			buf, cliaddr, err := receiveBytes(cliconn)
			if err != nil {
				t.Log("Could not read from socket")
				continue
			}
			clientAddress := cliaddr.String()
			_, ok := clientMap[clientAddress]
			if !ok {
				params := new(paramsPub)
				err = decodeData(buf, params)
				if err != nil {
					t.Log("Invalid params")
					continue
				}
				params.PubKey = new(big.Int).Set(params.Prime)
				newcli, _ := initClient(params, aes.BlockSize)
				err = sendData(params, servconn, nil)
				if err != nil {
					t.Log("could not send parameters to server")
					continue
				}
				clientMap[clientAddress] = newcli
				servPub := new(pubOnly)
				_, err := receiveData(servconn, servPub)
				if err != nil {
					t.Log("Could not receive pubkey from server")
					delete(clientMap, clientAddress)
					continue
				}
				servPub.PubKey = new(big.Int).Set(params.Prime)
				err = sendData(servPub, cliconn, cliaddr)
			} else {
				msg := new(dhEchoData)
				err := decodeData(buf, msg)
				padded := cbcDecrypt(msg.Data, msg.Iv, ciph)
				pt, err := pkcs7Unpad(padded)
				if err != nil {
					t.Logf("decryption error from %s", clientAddress)
					continue
				}
				t.Logf("c->s: %s", string(pt))
				err = sendData(msg, servconn, nil)
				if err != nil {
					t.Log("Could not relay message to server")
					continue
				}
				_, err = receiveData(servconn, msg)
				if err != nil {
					t.Log("Could not receive reply from server")
					continue
				}
				padded = cbcDecrypt(msg.Data, msg.Iv, ciph)
				pt, err = pkcs7Unpad(padded)
				t.Logf("c<-s: %s", string(pt))
				err = sendData(msg, cliconn, cliaddr)
			}
		}
	})
}

type dhParameters struct {
	Prime     *big.Int
	Generator *big.Int
}

func makeParams(p, g *big.Int) *dhParameters {
	result := new(dhParameters)
	result.Generator = new(big.Int).Set(g)
	result.Prime = new(big.Int).Set(p)
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
			cliParams.Generator = negoParams.Generator
			cliParams.Prime = negoParams.Prime
			cliParams.PubKey = nil
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
			cli.params.PubKey = remotePub.PubKey
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
	udpClient(hostname, port, func(conn *net.UDPConn) {
		defer conn.Close()
		params := new(dhParameters)
		params.Generator = g
		params.Prime = p
		myPriv := makeDHprivate(p)
		err := sendData(params, conn, nil)
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
		pubData.PubKey = makeDHpublic(params.Generator, params.Prime, myPriv)
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
		ciph, err := initDHCipher(aes.NewCipher, params.Prime, theirPub.PubKey, myPriv, aes.BlockSize)
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
	})
}

//runDHNegoParameterInjector injects a value given by ginject as follows:
//ginject = 0 injects p
//ginject = 1 injects 1
//ginject = -1 injects p-1
func runDHNegoParameterInjector(server string, serverPort, listenPort int, ginject *big.Int, t *testing.T) {
	//my private key = 2
	tmp := big.NewInt(2)
	cliconn, err := udpListen(listenPort)
	if err != nil {
		log.Fatalf("Could not listen on port %d", listenPort)
	}
	clientMap := make(map[string]*connState)

	var shared int64
	if ginject.Cmp(new(big.Int)) == 0 { // K = 0
		shared = 0
	} else { // K = 1
		shared = 1
	}

	key := sha1.Sum(big.NewInt(shared).Bytes())
	ciph, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		log.Println("Could not create shared cipher")
		return
	}

	udpClient(server, serverPort, func(servconn *net.UDPConn) {
		defer servconn.Close()

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
				params.Generator.Add(params.Prime, ginject).Mod(params.Generator, params.Prime)
				err = sendData(params, servconn, nil)
				if err != nil {
					log.Println("could not send parameters to server")
					continue
				}
				newcli := new(connState)
				newcli.ciph = nil
				newcli.pubKey = nil
				newcli.params = new(paramsPub)
				newcli.params.Generator = params.Generator
				newcli.params.Prime = params.Prime
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
				cli.params.PubKey = clipub.PubKey

				//send g'^t to both parties
				pubk := new(pubOnly)
				pubk.PubKey = bigPowMod(cli.params.Generator, tmp, cli.params.Prime)
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

				cli.ciph = ciph

			} else {
				msg := new(dhEchoData)
				err := decodeData(buf, msg)
				padded := cbcDecrypt(msg.Data, msg.Iv, cli.ciph)
				pt, err := pkcs7Unpad(padded)
				if err != nil {
					t.Logf("decryption error from %s", clientAddress)
					continue
				}
				t.Logf("c->s: %s", string(pt))
				err = sendData(msg, servconn, nil)
				if err != nil {
					t.Log("Could not relay message to server")
					continue
				}
				_, err = receiveData(servconn, msg)
				if err != nil {
					t.Log("Could not receive reply from server")
					continue
				}
				padded = cbcDecrypt(msg.Data, msg.Iv, cli.ciph)
				pt, err = pkcs7Unpad(padded)
				t.Logf("c<-s: %s", string(pt))
				err = sendData(msg, cliconn, cliaddr)
			}
		}
	})

}

type sRPParams struct {
	generator *big.Int
	k         *big.Int
	nistP     *big.Int
}

type sRPInput struct {
	id     string
	pass   string
	params sRPParams
}

func newSRPInput(id, pass string) *sRPInput {
	return &sRPInput{
		id,
		pass,
		sRPParams{
			big.NewInt(2),
			big.NewInt(3),
			getNistP(),
		},
	}
}

type sRPRecord struct {
	id   string
	salt string
	v    *big.Int
}

func newBigIntFromByteHash(h hash.Hash, in1 []byte, in2 []byte) *big.Int {
	h.Write(in1)
	h.Write(in2)
	xh := h.Sum(nil)
	return newBigIntFromBytes(xh[:h.Size()])
}

func (r *sRPRecord) Init(in *sRPInput, saltLen int) *sRPRecord {
	salt := randKey(saltLen)
	x := newBigIntFromByteHash(sha1.New(), salt, []byte(in.pass))
	v := bigPowMod(in.params.generator, x, in.params.nistP)
	x = nil

	r.id = in.id
	r.salt = base64Encode(salt)
	r.v = v

	return r
}

func sRPClientDerive(in *sRPInput, salt []byte, privA, pubB, u *big.Int) []byte {
	x := newBigIntFromByteHash(sha1.New(), salt, []byte(in.pass))
	exponent := new(big.Int).Add(privA, new(big.Int).Mul(u, x))
	gtox := bigPowMod(in.params.generator, x, in.params.nistP)
	base := new(big.Int).Sub(pubB, new(big.Int).Mul(in.params.k, gtox))
	shared := bigPowMod(base, exponent, in.params.nistP)
	retval := sha1.Sum(shared.Bytes())
	return retval[:sha1.Size]
}

func getSRPServerPub(priv *big.Int, rec *sRPRecord, params *sRPParams) *big.Int {
	kv := new(big.Int).Mul(params.k, rec.v)
	kv = kv.Mod(kv, params.nistP)
	gB := bigPowMod(params.generator, priv, params.nistP)
	retval := new(big.Int).Add(kv, gB)
	return retval.Mod(retval, params.nistP)
}

func sRPServerDerive(rec *sRPRecord, privB, pubA, u, nistP *big.Int) []byte {
	base := new(big.Int).Mul(pubA, bigPowMod(rec.v, u, nistP))
	shared := bigPowMod(base, privB, nistP)
	retval := sha1.Sum(shared.Bytes())
	return retval[:sha1.Size]
}

type sRPClientPub struct {
	ID  string
	Pub pubOnly
}

type sRPSeverPub struct {
	Salt []byte
	Pub  pubOnly
}

type sRPClientProof struct {
	Hash []byte
}

type sRPServerResult struct {
	Status []byte
}

func makeSRPClient(id, pass string, badInt *big.Int, t *testing.T, expect bool) func(*net.UDPConn) {
	return func(conn *net.UDPConn) {
		srpin := newSRPInput(id, pass)
		mypriv := makeDHprivate(srpin.params.nistP)
		mypub := new(sRPClientPub)
		mypub.ID = id
		mypub.Pub = *new(pubOnly)

		if badInt == nil {
			mypub.Pub.PubKey = makeDHpublic(srpin.params.generator, srpin.params.nistP, mypriv)
		} else {
			mypub.Pub.PubKey = badInt
		}

		err := sendData(mypub, conn, nil)
		if err != nil {
			t.Fatal("failed to send public key")
		}

		servPub := new(sRPSeverPub)
		_, err = receiveData(conn, servPub)
		if err != nil {
			t.Fatal("failed to receive server response")
		}

		var shared []byte
		if badInt == nil {
			shared = sRPClientDerive(
				srpin,
				servPub.Salt,
				mypriv,
				servPub.Pub.PubKey,
				newBigIntFromByteHash(
					sha1.New(),
					mypub.Pub.PubKey.Bytes(),
					servPub.Pub.PubKey.Bytes()))
		} else {
			zero := badInt.Mod(badInt, srpin.params.nistP).Bytes()
			h := sha1.Sum(zero)
			shared = h[:]
		}

		t.Log("Client shared: ", hexEncode(shared))
		proof := new(sRPClientProof)
		proof.Hash = hmacSha1(shared, servPub.Salt)
		err = sendData(proof, conn, nil)
		if err != nil {
			t.Fatal("could not send proof")
		}

		ciph := makeAES(shared[:aes.BlockSize])
		res := new(sRPServerResult)
		_, err = receiveData(conn, res)
		if err != nil {
			t.Fatal("failed to receive server response")
		}

		pt := cbcDecrypt(res.Status[aes.BlockSize:], res.Status[:aes.BlockSize], ciph)
		resultplain, err := pkcs7Unpad(pt)
		if err != nil && expect {
			t.Error("failed to decrypt server result")
		}

		if !expect {
			t.Log("failed to decrypt server result")
		} else {
			t.Log("Client result: ", string(resultplain))
		}

		result := string(resultplain) == "OK"
		if result != expect {
			t.Error("failed login with result:", result, "; expected:", expect)
		}
	}
}

func makeSRPServer(user *sRPInput, t *testing.T) func(*net.UDPConn) {
	rec := new(sRPRecord).Init(user, 16)

	return func(conn *net.UDPConn) {
		cliPub := new(sRPClientPub)
		addr, err := receiveData(conn, cliPub)
		if err != nil {
			t.Fatal("fail to receive initial client data")
		}

		servPub := new(sRPSeverPub)
		servPub.Salt = base64Decode(rec.salt)
		servPriv := makeDHprivate(user.params.nistP)
		servPub.Pub.PubKey = getSRPServerPub(servPriv, rec, &user.params)

		err = sendData(servPub, conn, addr)
		if err != nil {
			t.Fatal("failed to send back pubkey")
		}

		u := newBigIntFromByteHash(sha1.New(), cliPub.Pub.PubKey.Bytes(), servPub.Pub.PubKey.Bytes())
		shared := sRPServerDerive(rec, servPriv, cliPub.Pub.PubKey, u, user.params.nistP)
		t.Log("Server shared: ", hexEncode(shared))
		ciph := makeAES(shared[:aes.BlockSize])
		iv := randKey(aes.BlockSize)

		proof := new(sRPClientProof)
		addr, err = receiveData(conn, proof)
		if err != nil {
			t.Fatal("failed to receive client proof")
		}

		expected := hmacSha1(shared, servPub.Salt)

		var ok []byte
		if subtle.ConstantTimeCompare(proof.Hash, expected) == 1 {
			ok = []byte("OK")
		} else {
			ok = []byte("Go away")
		}

		t.Log("Server result: ", string(ok))
		ct := cbcEncrypt(pkcs7Pad(ok, aes.BlockSize), iv, ciph)
		data := make([]byte, len(iv)+len(ct))
		copy(data, iv)
		copy(data[len(iv):], ct)
		stat := new(sRPServerResult)
		stat.Status = data

		err = sendData(stat, conn, addr)

	}
}
