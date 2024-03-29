package cryptopals

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"math/big"
	mathrand "math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func hmacH(newHash func() hash.Hash, key, msg []byte) []byte {
	h := newHash()
	if len(key) > h.BlockSize() {
		hh := h.Sum(key)
		key = hh[:]
	}
	zeros := make([]byte, h.BlockSize())
	zlen := h.BlockSize() - len(key)
	if len(key) < h.BlockSize() {
		key = append(key, zeros[:zlen]...)
	}
	opad := bytes.Repeat([]byte{0x5c}, h.BlockSize())
	ipad := bytes.Repeat([]byte{0x36}, h.BlockSize())
	keyxoropad := xor(key, opad)
	keyxoripad := xor(key, ipad)
	inh := newHash()
	inh.Write(keyxoripad)
	inh.Write(msg)

	outh := newHash()
	outh.Write(keyxoropad)
	outh.Write(inh.Sum(nil))
	r := outh.Sum(nil)
	return r[:h.Size()]
}

func getNistP() *big.Int {
	const nistPstrs = `ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
	e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
	3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
	6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
	24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
	c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
	bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
	fffffffffffff`

	return hexStringToBigInt(flattenStr(nistPstrs))
}

func makeDHprivate(prime *big.Int) *big.Int {
	return newRandBigIntMod(prime)
}

func newBigIntFromBytes(in []byte) *big.Int {
	return new(big.Int).SetBytes(in)
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

var (
	zero  = big.NewInt(0)
	one   = big.NewInt(1)
	two   = big.NewInt(2)
	three = big.NewInt(3)
)

func bigPowMod(base, exp, mod *big.Int) *big.Int {
	result := new(big.Int).Set(one)
	base0 := new(big.Int).Set(base)
	exp0 := new(big.Int).Set(exp)
	mod2 := new(big.Int)

	for exp0.Sign() != 0 {
		mod2.And(exp0, one)
		if mod2.Sign() != 0 {
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

func dhKeyExchange(h hash.Hash, prime, pub, priv *big.Int) []byte {
	h.Reset()
	shared := bigPowMod(pub, priv, prime)
	h.Write(shared.Bytes())
	//priv.SetInt64(0)
	return h.Sum(nil)[:h.Size()]
}

const bufSize = uint16(1500)

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

// RunDHEchoClient runs dhEcho client with given args
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
	key := dhKeyExchange(sha256.New(), prime, remotePub, myPriv)
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
		if err == nil {
			break
		}
	}

	clientCb(conn)
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
	if err != nil {
		log.Panic(err)
	}
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

func udpServer(port int, server func(*net.UDPConn, *net.UDPAddr, []byte)) {
	listenAddr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
	conn, err := net.ListenUDP("udp4", &listenAddr)
	if err != nil {
		log.Fatalf("Could not listen on port %d: %s", port, err.Error())
	}

	for {
		tmpbuf, addr, err := receiveBytes(conn)
		if err != nil {
			log.Print("Error receiving packet")
			break
		}

		server(conn, addr, tmpbuf)
	}
}

func makeDHEchoServer() func(*net.UDPConn, *net.UDPAddr, []byte) {
	hostStateMap := make(map[string]*connState)
	var err error
	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		remoteAddr := addr.String()
		state, ok := hostStateMap[remoteAddr]
		if !ok {
			params := new(paramsPub)
			err = decodeData(buf, params)
			if err != nil {
				log.Printf("Invalid data on first packet from: %s", remoteAddr)
				return
			}
			newClient, err := initClient(params, aes.BlockSize)
			if err != nil {
				log.Printf("Invalid parameters on first packet from: %s", remoteAddr)
				return
			}
			err = sendData(newClient.pubKey, conn, addr)
			if err != nil {
				log.Printf("Error sending public key to %s", remoteAddr)
				return
			}
			hostStateMap[remoteAddr] = newClient
		} else {
			err = receiveMsgEchoReply(buf, conn, addr, state) //
			if err != nil {
				log.Printf("Could not receive message from: %s", remoteAddr)
				delete(hostStateMap, remoteAddr)
				return
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

func encodeData(data interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(data)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sendData(data interface{}, conn *net.UDPConn, addr *net.UDPAddr) error {
	buf, err := encodeData(data)
	if err != nil {
		return err
	}
	if addr != nil {
		_, err = conn.WriteTo(buf, addr)
	} else {
		_, err = conn.Write(buf)
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

func makeParameterInjector(
	server string, serverPort int,
	t *testing.T) func(*net.UDPConn, *net.UDPAddr, []byte) {

	shared := sha256.Sum256(new(big.Int).Bytes())
	ciph := makeAES(shared[:aes.BlockSize])
	clientMap := make(map[string]*connState)
	var err error
	return func(cliconn *net.UDPConn, cliaddr *net.UDPAddr, buf []byte) {
		defer cliconn.Close()

		udpClient(server, serverPort, func(servconn *net.UDPConn) {
			defer servconn.Close()

			for {
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
					_, err = receiveData(servconn, servPub)
					if err != nil {
						t.Log("Could not receive pubkey from server")
						delete(clientMap, clientAddress)
						continue
					}
					servPub.PubKey = new(big.Int).Set(params.Prime)
					err = sendData(servPub, cliconn, cliaddr)
				} else {
					msg := new(dhEchoData)
					err = decodeData(buf, msg)
					padded := cbcDecrypt(msg.Data, msg.Iv, ciph)
					var pt []byte
					pt, err = pkcs7Unpad(padded)
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
					if err != nil {
						log.Panic(err)
					}
					t.Logf("c<-s: %s", string(pt))
					err = sendData(msg, cliconn, cliaddr)
				}

				if err != nil {
					log.Panic(err)
				}

				buf, cliaddr, err = receiveBytes(cliconn)
				if err != nil {
					t.Logf("Failed to receive client %s bytes: %s", clientAddress, err.Error())
					return
				}
			}
		})
	}
}

type dhParameters struct {
	Prime     *big.Int
	Generator *big.Int
}

// func makeParams(p, g *big.Int) *dhParameters {
// 	result := new(dhParameters)
// 	result.Generator = new(big.Int).Set(g)
// 	result.Prime = new(big.Int).Set(p)
// 	return result
// }

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

func makeDHNegoEchoServer() func(*net.UDPConn, *net.UDPAddr, []byte) {
	cliMap := make(map[string]*connState)
	var err error
	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		remoteAddr := addr.String()
		cli, ok := cliMap[remoteAddr]
		if !ok {
			negoParams := new(dhParameters)
			err = decodeData(buf, negoParams)
			if err != nil {
				log.Printf("Could not decode data from %s", remoteAddr)
				return
			}
			ack := new(dhACK)
			err = sendData(ack, conn, addr)
			if err != nil {
				log.Printf("Could not send data to: %s", remoteAddr)
				return
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
				return
			}
			cli.params.PubKey = remotePub.PubKey
			newcli, err := initClient(cli.params, aes.BlockSize)
			if err != nil {
				log.Printf("Could not update client info with remote public key from %s", remoteAddr)
				delete(cliMap, remoteAddr)
				return
			}
			cli = newcli
			err = sendData(cli.pubKey, conn, addr)
			if err != nil {
				log.Printf("Could not send public key to %s", remoteAddr)
				delete(cliMap, remoteAddr)
				return
			}
			cliMap[remoteAddr] = newcli
		} else { //receive message
			err = receiveMsgEchoReply(buf, conn, addr, cli) //
			if err != nil {
				log.Printf("Could not receive message from: %s", remoteAddr)
				delete(cliMap, remoteAddr)
				return
			}
		}
	}
}

func makeDHNegoEchoTestClient(
	g, p *big.Int, numTests int, t *testing.T) func(*net.UDPConn) {
	return func(conn *net.UDPConn) {
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
	}
}

// runDHNegoParameterInjector injects a value given by ginject as follows:
// ginject = 0 injects p
// ginject = 1 injects 1
// ginject = -1 injects p-1
func makeDHNegoParameterInjector(
	server string, serverPort int,
	ginject *big.Int, t *testing.T) func(*net.UDPConn, *net.UDPAddr, []byte) {
	//my private key = 2
	tmp := big.NewInt(2)
	clientMap := make(map[string]*connState)

	var shared int64
	if ginject.Cmp(new(big.Int)) == 0 { // K = 0
		shared = 0
	} else { // K = 1
		shared = 1
	}

	key := sha256.Sum256(big.NewInt(shared).Bytes())
	ciph, err := aes.NewCipher(key[:aes.BlockSize])
	if err != nil {
		log.Println("Could not create shared cipher")
		return func(*net.UDPConn, *net.UDPAddr, []byte) {}
	}

	return func(cliconn *net.UDPConn, cliaddr *net.UDPAddr, buf []byte) {
		defer cliconn.Close()
		var err error
		udpClient(server, serverPort, func(servconn *net.UDPConn) {
			defer servconn.Close()

			for {
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
					err = decodeData(buf, msg)
					padded := cbcDecrypt(msg.Data, msg.Iv, cli.ciph)
					if err != nil {
						log.Panic(err)
					}

					var pt []byte
					pt, err = pkcs7Unpad(padded)
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

				buf, cliaddr, err = receiveBytes(cliconn)
			}
		})
	}
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
	h.Reset()
	h.Write(in1)
	h.Write(in2)
	xh := h.Sum(nil)
	return newBigIntFromBytes(xh[:h.Size()])
}

func (r *sRPRecord) Init(in *sRPInput, saltLen int) *sRPRecord {
	salt := randKey(saltLen)
	x := newBigIntFromByteHash(sha256.New(), salt, []byte(in.pass))
	v := bigPowMod(in.params.generator, x, in.params.nistP)
	x = nil

	r.id = in.id
	r.salt = base64Encode(salt)
	r.v = v

	return r
}

func sRPClientDerive(in *sRPInput, salt []byte, privA, pubB, u *big.Int) []byte {
	x := newBigIntFromByteHash(sha256.New(), salt, []byte(in.pass))
	exponent := new(big.Int).Add(privA, new(big.Int).Mul(u, x))
	gtox := bigPowMod(in.params.generator, x, in.params.nistP)
	base := new(big.Int).Sub(pubB, new(big.Int).Mul(in.params.k, gtox))
	shared := bigPowMod(base, exponent, in.params.nistP)
	retval := sha256.Sum256(shared.Bytes())
	return retval[:sha256.Size]
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
	retval := sha256.Sum256(shared.Bytes())
	return retval[:sha256.Size]
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
					sha256.New(),
					mypub.Pub.PubKey.Bytes(),
					servPub.Pub.PubKey.Bytes()))
		} else {
			zero := badInt.Mod(badInt, srpin.params.nistP).Bytes()
			h := sha256.Sum256(zero)
			shared = h[:]
		}

		t.Log("Client shared: ", hexEncode(shared))
		proof := new(sRPClientProof)
		proof.Hash = hmacH(sha256.New, shared, servPub.Salt)
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

func makeSRPServer(user *sRPInput, t *testing.T) func(*net.UDPConn, *net.UDPAddr, []byte) {
	rec := new(sRPRecord).Init(user, 16)

	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		defer conn.Close()

		for {
			cliPub := new(sRPClientPub)
			err := decodeData(buf, cliPub)
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

			u := newBigIntFromByteHash(sha256.New(), cliPub.Pub.PubKey.Bytes(), servPub.Pub.PubKey.Bytes())
			shared := sRPServerDerive(rec, servPriv, cliPub.Pub.PubKey, u, user.params.nistP)
			t.Log("Server shared: ", hexEncode(shared))
			ciph := makeAES(shared[:aes.BlockSize])
			iv := randKey(aes.BlockSize)

			proof := new(sRPClientProof)
			addr, err = receiveData(conn, proof)
			if err != nil {
				t.Fatal("failed to receive client proof")
			}

			expected := hmacH(sha256.New, shared, servPub.Salt)

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
			if err != nil {
				log.Panic(err)
			}
			buf, addr, err = receiveBytes(conn)
			if err != nil {
				log.Panic(err)
			}
		}
	}
}

type simpleSRPServerPub struct {
	Salt []byte
	Pub  pubOnly
	U    *big.Int
}

func makeSimpleSRPServer(user *sRPInput, t *testing.T) func(*net.UDPConn, *net.UDPAddr, []byte) {
	rec := new(sRPRecord).Init(user, 16)

	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		defer conn.Close()
		avu := new(big.Int)
		servPub := new(simpleSRPServerPub)
		servPub.Salt = base64Decode(rec.salt)
		servPriv := makeDHprivate(user.params.nistP)
		servPub.Pub.PubKey = makeDHpublic(user.params.generator, user.params.nistP, servPriv)
		servPub.U = new(big.Int).SetBytes(randKey(16))

		for {
			cliPub := new(sRPClientPub)
			err := decodeData(buf, cliPub)
			if err != nil {
				t.Fatal("fail to receive initial client data")
			}

			err = sendData(servPub, conn, addr)
			if err != nil {
				t.Fatal("failed to send back pubkey")
			}

			vu := bigPowMod(rec.v, servPub.U, user.params.nistP)
			avu.Mul(cliPub.Pub.PubKey, vu).Mod(avu, user.params.nistP)

			shared := dhKeyExchange(sha256.New(), user.params.nistP, avu, servPriv)
			t.Log("Server shared: ", hexEncode(shared))
			ciph := makeAES(shared[:aes.BlockSize])
			iv := randKey(aes.BlockSize)

			proof := new(sRPClientProof)
			addr, err = receiveData(conn, proof)
			if err != nil {
				t.Fatal("failed to receive client proof")
			}

			expected := hmacH(sha256.New, shared, servPub.Salt)

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
			if err != nil {
				t.Fatal(err)
			}
			buf, addr, err = receiveBytes(conn)
			if err != nil {
				t.Fatal(err)
			}
		}
	}

}

func makeSimpleSRPClient(id, pass string, t *testing.T, expect bool) func(conn *net.UDPConn) {
	exp := new(big.Int)
	ux := new(big.Int)
	return func(conn *net.UDPConn) {
		srpin := newSRPInput(id, pass)
		mypriv := makeDHprivate(srpin.params.nistP)
		mypub := new(sRPClientPub)
		mypub.ID = id
		mypub.Pub = *new(pubOnly)

		mypub.Pub.PubKey = makeDHpublic(srpin.params.generator, srpin.params.nistP, mypriv)

		err := sendData(mypub, conn, nil)
		if err != nil && t != nil {
			t.Error("failed to send public key")
			return
		}

		servPub := new(simpleSRPServerPub)
		_, err = receiveData(conn, servPub)
		if err != nil && t != nil {
			t.Error("failed to receive server response")
			return
		}

		x := newBigIntFromByteHash(sha256.New(), servPub.Salt, []byte(srpin.pass))
		exp.Add(mypriv, ux.Mul(servPub.U, x))
		shared := dhKeyExchange(sha256.New(), srpin.params.nistP, servPub.Pub.PubKey, exp)

		if t != nil {
			t.Log("Client shared: ", hexEncode(shared))
		}
		proof := new(sRPClientProof)
		proof.Hash = hmacH(sha256.New, shared, servPub.Salt)
		err = sendData(proof, conn, nil)
		if err != nil && t != nil {
			t.Error("could not send proof")
			return
		}

		ciph := makeAES(shared[:aes.BlockSize])
		res := new(sRPServerResult)
		_, err = receiveData(conn, res)
		if err != nil && t != nil {
			t.Error("failed to receive server response")
			return
		}

		pt := cbcDecrypt(res.Status[aes.BlockSize:], res.Status[:aes.BlockSize], ciph)
		resultplain, err := pkcs7Unpad(pt)
		if err != nil && t != nil && expect {
			t.Error("failed to decrypt server result")
			return
		}

		if t != nil {
			t.Log("Client result: ", string(resultplain))
		}

		result := string(resultplain) == "OK"
		if result != expect && t != nil {
			t.Error("failed login with result:", result)
		}

		if t != nil {
			t.Log("Client exiting")
		}
	}
}

func makeSimpleSRPCracker(params *sRPParams, wordlist []string, t *testing.T, response chan string) func(*net.UDPConn, *net.UDPAddr, []byte) {

	return func(conn *net.UDPConn, addr *net.UDPAddr, buf []byte) {
		defer conn.Close()

		servPub := new(simpleSRPServerPub)
		servPub.Salt = randKey(16) //salt length
		servPriv := makeDHprivate(params.nistP)
		servPub.Pub.PubKey = makeDHpublic(params.generator, params.nistP, servPriv)
		servPub.U = new(big.Int).SetBytes(randKey(16))
		v := new(big.Int)
		vu := new(big.Int)
		avu := new(big.Int)

		for {
			cliPub := new(sRPClientPub)
			err := decodeData(buf, cliPub)
			if err != nil {
				t.Fatal("fail to receive initial client data")
			}

			err = sendData(servPub, conn, addr)
			if err != nil {
				t.Fatal("failed to send back pubkey")
			}

			proof := new(sRPClientProof)
			addr, err = receiveData(conn, proof)
			if err != nil {
				t.Fatal("failed to receive client proof")
			}

			resp := new(sRPServerResult)
			resp.Status = randKey(16)
			err = sendData(resp, conn, addr)
			if err != nil {
				log.Panic(err)
			}
			h := sha256.New()
			for i, pass := range wordlist {
				x := newBigIntFromByteHash(h, servPub.Salt, []byte(pass))
				v.Exp(params.generator, x, params.nistP)
				vu.Exp(v, servPub.U, params.nistP)
				avu.Mul(cliPub.Pub.PubKey, vu).Mod(avu, params.nistP)
				shared := dhKeyExchange(h, params.nistP, avu, servPriv)
				thisHmac := hmacH(sha256.New, shared, servPub.Salt)

				if bytes.Equal(thisHmac, proof.Hash) {
					response <- pass
					fmt.Println()
					return
				}

				if i == 0 {
					h.Reset()
					continue
				}

				if i%10 == 0 {
					fmt.Print(".")
				}

				if i%100 == 0 {
					fmt.Printf("%d\n", i)
				}

				h.Reset()
			}

			response <- ""
		}
	}
}

func loadWordList(fileName string) []string {
	return strings.FieldsFunc(string(readFile(fileName)),
		func(r rune) bool {
			return r == '\n' || r == '\r'
		})
}

func extEuclidean(a, b *big.Int) (gcd, s, t *big.Int) {
	if a.Cmp(b) < 0 {
		rgcd, rt, rs := extEuclidean(b, a)
		return rgcd, rs, rt
	}

	s, oldS := big.NewInt(0), big.NewInt(1)
	t, oldT := big.NewInt(1), big.NewInt(0)
	r, oldR := new(big.Int).Set(b), new(big.Int).Set(a)
	sub := new(big.Int)
	quo := new(big.Int)
	quoS := new(big.Int)
	quoT := new(big.Int)
	mod := new(big.Int)

	for r.Sign() != 0 {
		quo.DivMod(oldR, r, mod)
		oldR.Set(r)
		r.Set(mod)
		sub.Sub(oldS, quoS.Mul(quo, s))
		oldS.Set(s)
		s.Set(sub)
		sub.Sub(oldT, quoT.Mul(quo, t))
		oldT.Set(t)
		t.Set(sub)
	}

	return oldR, oldS, oldT
}

// invMod finds the multiplicative inverse of a modulo n
// or b s.t. ab = 1 mod n
// or b s.t. ab = 1 + qn
// or b s.t. ab + qn = 1
// or s s.t. as + nt = 1 (gcd)
// returns inverse or 0 on error
func invMod(a, n *big.Int) (*big.Int, error) {
	gcd, s, _ := extEuclidean(a, n)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("no invmod of " + a.String() + " mod " + n.String() + " exists")
	}

	for s.Sign() < 0 {
		s.Add(s, n)
	}
	return s, nil
}

type rsaPrivate struct {
	d    *big.Int
	dP   *big.Int
	dQ   *big.Int
	qInv *big.Int
	p    *big.Int
	q    *big.Int
	n    *big.Int
}

type rsaPublic struct {
	E *big.Int
	N *big.Int
}

type rsaKeyPair struct {
	Private *rsaPrivate
	Public  *rsaPublic
}

func randomCoprimeP1(coprime *big.Int, bits int) (*big.Int, error) {
	rem := new(big.Int)
	p := new(big.Int)
	pBytes := make([]byte, bits/8)
	primeTests := 64

	for {
		fmt.Fprintf(os.Stderr, ".")
		if _, err := io.ReadFull(rand.Reader, pBytes); err != nil {
			return nil, err
		}
		pBytes[0] |= 0x80
		pBytes[len(pBytes)-1] |= 0x01
		p.SetBytes(pBytes)

		rem.Mod(p, coprime)
		rem.Sub(rem, two)
		p.Sub(p, rem)

		if p.BitLen() < bits {
			continue
		}

		if p.ProbablyPrime(primeTests) {
			break
		}

	}

	fmt.Fprintln(os.Stderr, "++")
	return p, nil
}

func genRSAPrivate(bits int) (*rsaPrivate, error) {
	e := new(big.Int).Set(three)
	ret := &rsaPrivate{}
	var err error
	ret.p, err = randomCoprimeP1(e, bits)
	if err != nil {
		return nil, err
	}
	p1 := new(big.Int).Sub(ret.p, one)

	ret.q, err = randomCoprimeP1(e, bits)
	if err != nil {
		return nil, err
	}

	q1 := new(big.Int).Sub(ret.q, one)
	tot := new(big.Int).Mul(p1, q1)
	ret.d, err = invMod(e, tot)
	if err != nil {
		return nil, err
	}
	ret.dP, err = invMod(e, p1)
	if err != nil {
		return nil, err
	}
	ret.dQ, err = invMod(e, q1)
	if err != nil {
		return nil, err
	}
	ret.qInv, err = invMod(ret.q, ret.p)
	if err != nil {
		return nil, err
	}
	ret.n = new(big.Int).Mul(ret.p, ret.q)

	return ret, nil
}

func getRSAPublic(priv *rsaPrivate) *rsaPublic {
	if priv == nil {
		return nil
	}

	return &rsaPublic{
		big.NewInt(3),
		new(big.Int).Set(priv.n)}
}

func rsaEncrypt(pubkey *rsaPublic, in []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(in)
	if m.Cmp(pubkey.N) > 0 {
		return nil, errors.New("invalid message length")
	}

	return bigPowMod(m, pubkey.E, pubkey.N).Bytes(), nil
}

func rsaDecrypt(privkey *rsaPrivate, in []byte) ([]byte, error) {
	c := newBigIntFromBytes(in)
	if c.Cmp(privkey.n) > 0 {
		return nil, errors.New("invalid ciphertext")
	}

	m1 := bigPowMod(c, privkey.dP, privkey.p)
	m2 := bigPowMod(c, privkey.dQ, privkey.q)
	h := new(big.Int).Sub(m1, m2)
	if h.Sign() < 0 {
		h.Add(h, privkey.p)
	}
	h.Mul(h, privkey.qInv).Mod(h, privkey.p)
	h.Mul(h, privkey.q).Add(h, m2)
	return h.Bytes(), nil
}

func genRSAKeyPair(bits int) (*rsaKeyPair, error) {
	for {
		priv, err := genRSAPrivate(bits / 2)
		if err != nil {
			return nil, err
		}
		pub := getRSAPublic(priv)

		if pub.N.BitLen() == bits {
			return &rsaKeyPair{priv, pub}, nil
		}
	}
}

func isPairwiseCoprime(pubKey0, pubKey1, pubKey2 *rsaPublic) bool {
	gcd01, _, _ := extEuclidean(pubKey0.N, pubKey1.N)
	gcd12, _, _ := extEuclidean(pubKey1.N, pubKey2.N)
	gcd02, _, _ := extEuclidean(pubKey0.N, pubKey2.N)

	if gcd01.Cmp(one) != 0 ||
		gcd12.Cmp(one) != 0 ||
		gcd02.Cmp(one) != 0 {
		return false
	}

	return true
}

func rsaCubeDecrypt(
	pubKey0, pubKey1, pubKey2 *rsaPublic,
	c0, c1, c2 []byte) ([]byte, error) {
	if pubKey0.E.Cmp(three) != 0 ||
		pubKey1.E.Cmp(three) != 0 ||
		pubKey2.E.Cmp(three) != 0 {
		return nil, errors.New("cubeDecrypt needs pubkey exponen = 3")
	}

	if !isPairwiseCoprime(pubKey0, pubKey1, pubKey2) {
		return nil, errors.New("public keys are not pairwise coprime")
	}

	ct0 := newBigIntFromBytes(c0)
	ct1 := newBigIntFromBytes(c1)
	ct2 := newBigIntFromBytes(c2)
	ms0 := new(big.Int).Mul(pubKey1.N, pubKey2.N)
	ms1 := new(big.Int).Mul(pubKey0.N, pubKey2.N)
	ms2 := new(big.Int).Mul(pubKey0.N, pubKey1.N)
	n012 := new(big.Int).Mul(pubKey0.N, pubKey1.N)
	n012.Mul(n012, pubKey2.N)

	invms0n0, err := invMod(ms0, pubKey0.N)
	if err != nil {
		return nil, err
	}

	invms1n1, err := invMod(ms1, pubKey1.N)
	if err != nil {
		return nil, err
	}

	invms2n2, err := invMod(ms2, pubKey2.N)
	if err != nil {
		return nil, err
	}

	t0 := new(big.Int).Mul(ct0, ms0)
	t0.Mul(t0, invms0n0)
	t1 := new(big.Int).Mul(ct1, ms1)
	t1.Mul(t1, invms1n1)
	t2 := new(big.Int).Mul(ct2, ms2)
	t2.Mul(t2, invms2n2)

	res := new(big.Int).Add(t0, t1)
	res.Add(res, t2)
	res.Mod(res, n012)

	x, err := cubeRoot(res)
	if err != nil {
		return nil, err
	}
	return x.Bytes(), nil
}

func cubeRoot(a *big.Int) (*big.Int, error) {
	if a.Sign() == 0 ||
		a.Cmp(one) == 0 {
		return a, nil
	}

	if a.Sign() < 0 {
		return nil, errors.New("negative root not supported")
	}

	setBit := a.BitLen()/3 + 1
	x := new(big.Int).SetBit(zero, setBit, 1)
	y := big.NewInt(0)
	x2 := new(big.Int)
	frac := new(big.Int)
	for {
		y.Lsh(x, 1)
		y.Add(y, frac.Div(a, x2.Mul(x, x)))
		y.Div(y, three)

		if y.Cmp(x) >= 0 {
			break
		}
		x.Set(y)
	}

	return x, nil
}
