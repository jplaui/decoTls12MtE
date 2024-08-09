package tls

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/ubiq/go-ubiq/common/hexutil"
	"log"
	"math/big"
	"net"
	"os/exec"
	"strings"
)

func RunVerifier(ipAddr string, port string, caPath string, config *Config) {

	addr := ipAddr + ":" + port

	config.Rand = rand.Reader
	listener, err := Listen("tcp", addr, config)
	if err != nil {
		log.Fatalf("verifier: listen: %s", err)
	}
	log.Print("verifier: listening")
	vLocalStorage := &verifierLocalStorage{}
	for {
		if vLocalStorage.countMtAType == 3 {
			vLocalStorage = &verifierLocalStorage{}
		}
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("verifier: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("verifier: accepted from %s", conn.RemoteAddr())

		_, ok := conn.(*Conn)
		if ok {
			log.Print("verifier: ok=true")
		}

		go handleProverVerifierCommunication(conn, vLocalStorage, config.PathConfig)

	}
}

func handleProverVerifierCommunication(conn net.Conn, vLocalStorage *verifierLocalStorage, decoConfig *PathConfig) {
	path := decoConfig.Path.MPC
	defer conn.Close()
	tlsConn, ok := conn.(*Conn)
	if !ok {
		log.Print("verifier: conn is not a TLS conn")
	}

	var err error
	pSendMsg := &proverSendMsg{}
	vRespMsg := &verifierResponseMsg{}
	decoder := json.NewDecoder(conn)
	decoder.Decode(&pSendMsg)
	printDebugInfoFromProverSendMsg(pSendMsg)
	////pSendMsgByteFormat, err := json.Marshal(&pSendMsg)
	//if err != nil {
	//	log.Printf("verifier: json corrupt %s", err)
	//}
	////fmt.Println(string(pSendMsgByteFormat))

	//TODO: pSendMsg.MessageType == Test is ONLY FOR DEBUGING, NOT USED IN FINAL PRODUCTION
	if pSendMsg.MessageType == Test {
		var s1 []byte
		decoder := json.NewDecoder(conn)
		decoder.Decode(&pSendMsg)
		s1 = pSendMsg.S
		printDebugInfoFromByte(s1, "s1")
		s11 := new(big.Int).SetBytes(s1)
		printDebugInfoFromString(hexutil.EncodeBig(s11), "s1 in hex")
		is := new(big.Int).Add(vLocalStorage.s, s11)
		printDebugInfoFromString(hexutil.EncodeBig(vLocalStorage.s), "s2 in hex")
		stotal := new(big.Int).Mod(is, vLocalStorage.p)
		vLocalStorage.keyShare = stotal
		printDebugInfoFromString(hexutil.EncodeBig(stotal), "s1+s2 in hex")
		printDebugInfoFromString(hexutil.EncodeBig(vLocalStorage.p), "p in hex")

		printDebugInfoFromBigInt(stotal, "s1+s2")
		vLocalStorage.countMtAType = 0
		return
	} else if pSendMsg.MessageType == SharedPreMasterKey {
		vRespMsg := new(verifierResponseMsg)
		vRespMsg.MessageType = SharedPreMasterKey
		vRespMsg.SharePreMasterKey = vLocalStorage.keyShare.Bytes()
		encoder := json.NewEncoder(conn)
		encoder.Encode(&vRespMsg)

		party := "2"
		port := "12345"
		s1 := "00000000000000000000000000000000000000000000000000000000000000000"
		s2 := "0" + fillStringInputFormat(vLocalStorage.s.Text(16), 64)
		cRandom := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.RandomProver).Text(16), 64)
		sRandom := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.RandomServer).Text(16), 64)
		printDebugInfoFromString(s2, "S2")
		printDebugInfoFromString(cRandom, "cRandom")
		printDebugInfoFromString(sRandom, "sRandom")
		cmd := exec.Command(path+"/prf", party, port, s1, s2, cRandom, sRandom)
		data, _ := cmd.Output()
		printDebugInfoFromString(string(data), "2pc finished-")
		hs2PCOut := outputStringVerifierProcess(data)
		//fmt.Println(new(big.Int).SetBytes(hs2PCOut.xorKeyClientMac).Text(16))
		//fmt.Println(new(big.Int).SetBytes(hs2PCOut.xorMasterSecrete).Text(16))
		vLocalStorage.hs2PCOut = hs2PCOut
		vLocalStorage.clearVerifierLocalStorage()
		return
	} else if pSendMsg.MessageType == Start3PHandshakePRF2PC {
		party := "2"
		port := "12345"
		s1 := strings.Repeat("0", 64+1)
		s2 := "0" + fillStringInputFormat(vLocalStorage.s.Text(16), 64)
		cRandom := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.RandomProver).Text(16), 64)
		sRandom := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.RandomServer).Text(16), 64)
		printDebugInfoFromString(s2, "S2")
		printDebugInfoFromString(cRandom, "cRandom")
		printDebugInfoFromString(sRandom, "sRandom")

		cmd := exec.Command(path+"/prf", party, port, s1, s2, cRandom, sRandom)
		data, _ := cmd.Output()
		printDebugInfoFromString(string(data), "2pc finished-")
		hs2PCOut := outputStringVerifierProcess(data)
		//fmt.Println(new(big.Int).SetBytes(hs2PCOut.xorKeyClientMac).Text(16))
		//fmt.Println(new(big.Int).SetBytes(hs2PCOut.xorMasterSecrete).Text(16))
		vLocalStorage.hs2PCOut = hs2PCOut
		vLocalStorage.clearVerifierLocalStorage()
		return
	} else if pSendMsg.MessageType == StartClientFinished2PC {
		party := "2"
		port := "12345"

		pKeyMasterSecret := strings.Repeat("0", 96)
		vKeyMasterSecret := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorMasterSecrete).Text(16), 96)
		printDebugInfoFromString(pKeyMasterSecret, "pKeyMasterSecret")
		printDebugInfoFromString(vKeyMasterSecret, "vKeyMasterSecret")
		outHash := strings.Repeat("0", 64)

		cmd := exec.Command(path+"/prf_client_finished", party, port, pKeyMasterSecret, vKeyMasterSecret, outHash)
		data, _ := cmd.Output()
		printDebugInfoFromString(string(data), "2pc client finished step finished")

		//proverKeyMac := strings.Repeat("0", 64)
		//verifierKeyMac := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorKeyClientMac).Text(16), 64)
		//cmd = exec.Command(path+"/hmac_setup", party, port, proverKeyMac, verifierKeyMac)
		//data, _ = cmd.Output()
		//printDebugInfoFromString(string(data), "hmac setup finished")
		//
		//innerSecondHash := strings.Repeat("0", 64)
		//cmd = exec.Command(path+"/hmac_outer_hash", party, port, proverKeyMac, verifierKeyMac, innerSecondHash)
		//data, _ = cmd.Output()
		//printDebugInfoFromString(string(data), "2pc hmac finished")

		return
	} else if pSendMsg.MessageType == StartServerFinished2PC {
		party := "2"
		port := "12345"

		pKeyMasterSecret := strings.Repeat("0", 96)
		vKeyMasterSecret := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorMasterSecrete).Text(16), 96)
		printDebugInfoFromString(pKeyMasterSecret, "pKeyMasterSecret")
		printDebugInfoFromString(vKeyMasterSecret, "vKeyMasterSecret")
		outHash := strings.Repeat("0", 64)

		cmd := exec.Command(path+"/prf_server_finished", party, port, pKeyMasterSecret, vKeyMasterSecret, outHash)
		data, _ := cmd.Output()
		printDebugInfoFromString(string(data), "2pc server finished step finished")
		return
	} else if pSendMsg.MessageType == StartApp2PCHMac {

		party := "2"
		port := "12345"
		proverKeyMac := strings.Repeat("0", 64)
		verifierKeyMac := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorKeyClientMac).Text(16), 64)
		cmd := exec.Command(path+"/hmac_setup", party, port, proverKeyMac, verifierKeyMac)
		data, _ := cmd.Output()
		printDebugInfoFromString(string(data), "hmac setup finished")

		innerSecondHash := strings.Repeat("0", 64)
		cmd = exec.Command(path+"/hmac_outer_hash", party, port, proverKeyMac, verifierKeyMac, innerSecondHash)
		data, _ = cmd.Output()
		printDebugInfoFromString(string(data), "2pc hmac finished")
		return
	} else if pSendMsg.MessageType == StartSer2PCHMac {

		party := "2"
		port := "12345"
		proverKeyMac := strings.Repeat("0", 64)
		verifierKeyMac := fillStringInputFormat(new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorKeyServerMac).Text(16), 64)
		cmd := exec.Command(path+"/hmac_setup", party, port, proverKeyMac, verifierKeyMac)
		fmt.Println("start hmac_setup1.....")
		data, _ := cmd.Output()
		fmt.Println("start hmac_setup2.....")
		printDebugInfoFromString(string(data), "hmac server setup finished")
		fmt.Println("start hmac_setup3.....")
		innerSecondHash := strings.Repeat("0", 64)
		fmt.Println("start hmac outer hash.....")
		cmd = exec.Command(path+"/hmac_outer_hash", party, port, proverKeyMac, verifierKeyMac, innerSecondHash)
		data2, _ := cmd.Output()
		fmt.Println("start hmac outer hash finished.....")
		printDebugInfoFromString(string(data2), "2pc server hmac finished")
		return
	} else if pSendMsg.MessageType == ProverCommitMessage {
		vRespMsg = new(verifierResponseMsg)
		vRespMsg.MessageType = VerifierMacKeyMessage
		vRespMsg.XorClientMac = vLocalStorage.hs2PCOut.xorKeyClientMac
		vRespMsg.XorServerMac = vLocalStorage.hs2PCOut.xorKeyServerMac
		vLocalStorage.cipherQuery = pSendMsg.CommitCipherQuery
		vLocalStorage.cipherResponse = pSendMsg.CommitCipherResp
		vLocalStorage.rKeyMac = pSendMsg.CommitRKeyMac
		encoder := json.NewEncoder(conn)
		encoder.Encode(&vRespMsg)
		printDebugInfoFromVerifierResponseMsg(vRespMsg)
		return
	} else if pSendMsg.MessageType == ZKSNARKVerify {
		si := SHA256CompressionFunction(pSendMsg.BiMinus)
		siStr := fillStringInputFormat(new(big.Int).SetBytes(si).Text(16), 32*2)
		printDebugInfoFromString(siStr, "si")
		ivForLast3Blocks := pSendMsg.IVForLast3Blocks
		ivForLast3BlocksStr := fillStringInputFormat(new(big.Int).SetBytes(ivForLast3Blocks).Text(16), 16*2)
		printDebugInfoFromString(ivForLast3BlocksStr, "iv for last 3 blocks ")
		padding := pSendMsg.Padding
		paddingStr := fillStringInputFormat(new(big.Int).SetBytes(padding).Text(16), len(padding)*2)
		printDebugInfoFromString(paddingStr, "padding")
		blkLength := len(vLocalStorage.cipherResponse)
		last3BlocksLen := 48
		cipherSigmaBlock := make([]byte, last3BlocksLen)
		copy(cipherSigmaBlock, vLocalStorage.cipherResponse[blkLength-last3BlocksLen:blkLength])
		cipherSigmaBlockStr := fillStringInputFormat(new(big.Int).SetBytes(cipherSigmaBlock).Text(16), 48*2)
		printDebugInfoFromString(cipherSigmaBlockStr, "encrypted sigma")

		onChainCommit := "aa8586ce4ae9d6799733c8f849397c39fdc9f9c2fd3ead72b2c6011b80795967"
		i1 := new(big.Int).SetBytes(vLocalStorage.hs2PCOut.xorKeyServerMac)
		i2 := new(big.Int).SetBytes(vLocalStorage.rKeyMac)
		serverMAC := new(big.Int).Xor(i1, i2).Bytes()
		serverMACStr := fillStringInputFormat(new(big.Int).SetBytes(serverMAC).Text(16), 32*2)
		cmd2 := exec.Command(decoConfig.Path.Libsnark+decoConfig.File.Verifier,
			siStr, ivForLast3BlocksStr, serverMACStr, paddingStr, cipherSigmaBlockStr, onChainCommit)
		cmd2.Dir = decoConfig.Path.Out
		data, _ := cmd2.Output()
		printDebugInfoFromString(string(data), "verify info")
		dataLen := len(data)
		log.Printf("verifier: zkSNARK result %s", string(data[dataLen-5:]))
		return
	}

	if err = pSendMsg.checkProverSendMsg(); err != nil {
		log.Printf("verifier: %s", err)
		return
	}

	var msgHandler verifierMessageHandler
	switch pSendMsg.MessageType {
	case ProverCommSetupMessage:
		msgHandler = new(verifierKeyExchangeHandler)
	case ProverMtAMessage:
		msgHandler = new(verifierMtAProverHandler)
	case ProverDeltaMessage:
		msgHandler = new(verifierDeltaHandler)
	case ProverMtAMessageScalar:
		msgHandler = new(verifierMtAScalarHandler)
	}

	msgHandler.Set(pSendMsg, vRespMsg, vLocalStorage)
	vRespMsg, vLocalStorage = msgHandler.handle(tlsConn)
	if err = vRespMsg.checkVerifierResponseMsg(); err != nil {
		log.Printf("verifier: %s", err)
		return
	}
	encoder := json.NewEncoder(conn)
	encoder.Encode(&vRespMsg)
	printDebugInfoFromVerifierResponseMsg(vRespMsg)
	////vRespMsgByte, err := json.Marshal(vRespMsg)
	////fmt.Println(string(vRespMsgByte))
	//if err != nil {
	//	log.Printf("verifier: verifier's response data format not corrupted: %s", err)
	//}

	switch h := msgHandler.(type) {
	case *verifierDeltaHandler:
		h.afterTransport()
		log.Println("verifier: eta calculation finished")
	case *verifierMtAScalarHandler:
		h.afterTransport()
		log.Print("verifier: s calculation finished")
		printDebugInfoFromBigInt(h.vLocalStorage.s, "s2")
		vLocalStorage.countMtAType = 0
	default:

	}
	log.Print("verifier: response successfully")

}
