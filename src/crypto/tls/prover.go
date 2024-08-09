package tls

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/didiercrunch/paillier"
	"io/ioutil"
	"log"
	"math/big"
)

func setDefaultProverConfig(certificatePath string, run3PHSProtocol bool, httpUrl string) *Config {

	caCert, err := ioutil.ReadFile(certificatePath)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	config := Config{
		RootCAs:                  caCertPool,
		CurvePreferences:         []CurveID{CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               VersionTLS12,
		MaxVersion:               VersionTLS12,
		CipherSuites: []uint16{
			TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		},
		ClientSessionCache:     NewLRUClientSessionCache(32),
		Run3PHSProtocol:        run3PHSProtocol,
		LocalCACertificatePath: certificatePath,
		VerifierHttpUrl:        httpUrl,
	}
	return &config
}

func (c *Conn) runCommunicationWithVerifier(verifierAddress string, localCACertPath string, pSendMsg *proverSendMsg, pStore *proverLocalStorage) *verifierResponseMsg {

	if c.config.ProverInternalConfig == nil {
		c.config.ProverInternalConfig = setDefaultProverConfig(localCACertPath, false, verifierAddress)
	}

	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())

	encoder := json.NewEncoder(conn)
	encoder.Encode(pSendMsg)
	if err = pSendMsg.checkProverSendMsg(); err != nil {
		log.Printf("prover: %s", err)
		log.Println("prover: PV round failed")
		return nil
	}
	printDebugInfoFromProverSendMsg(pSendMsg)

	var vRespMsg *verifierResponseMsg

	decoder := json.NewDecoder(conn)
	decoder.Decode(&vRespMsg)
	if err = vRespMsg.checkVerifierResponseMsg(); err != nil {
		log.Printf("prover: %s", err)
		log.Println("prover: PV round failed")
		return nil
	}

	var msgHandler proverMessageHandler
	switch vRespMsg.MessageType {
	case VerifierCommSetupResponseMessage:
		msgHandler = new(proverKeyExchangeHandler)
	case VerifierMtAResponseMessage:
		msgHandler = new(proverMtAHandler)
	case VerifierDeltaResponseMessage:
		msgHandler = new(proverDeltaHandler)
	case VerifierMtAScalarResponseMessage:
		msgHandler = new(proverMtAScalarHandler)
	}
	msgHandler.Set(pSendMsg, vRespMsg, pStore)
	msgHandler.handle(pSendMsg, vRespMsg)

	printDebugInfoFromVerifierResponseMsg(vRespMsg)

	switch h := msgHandler.(type) {
	case *proverDeltaHandler:
		h.afterTransport()
		log.Print("prover: eta calculation finished")
	case *proverMtAScalarHandler:
		h.afterTransport()
		log.Print("prover: s calculation finished")
		//time.Sleep(5e9)

	default:

	}

	log.Print("prover: PV round successfully finished")
	return vRespMsg
}

func (c *Conn) constructProverCommSetupMessage(hs *clientHandshakeState, certMsg *certificateMsg, skx *serverKeyExchangeMsg, pStore *proverLocalStorage) *proverSendMsg {
	pMsg := &proverSendMsg{
		MessageType:           ProverCommSetupMessage,
		TLSVersion:            c.vers,
		CipherSuite:           hs.suite.id,
		RandomServer:          hs.serverHello.random,
		RandomProver:          hs.hello.random,
		ServerCertificate:     certMsg.raw,
		ServerKeyAndSigParams: skx.key,
	}
	pStore.curveID = CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	curve, _ := curveForCurveID(pStore.curveID)
	pStore.p = curve.Params().P
	return pMsg
}

func (c *Conn) constructProverMtAMessageTypeVector(proverECtF *ProverECtF, skx *serverKeyExchangeMsg, ka *ecdheKeyAgreement,
	sendX bool, pStore *proverLocalStorage) (*proverSendMsg, error) {
	curveID := CurveID(skx.key[1])<<8 | CurveID(skx.key[2])
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("prover: unsupported curve inclusive X25519")
	}
	if pStore.countMtAType == 0 {
		err := proverECtF.ectf.GenerateRandomElementInVector(curve.Params().P, c.config.rand())
		if err != nil {
			return nil, errors.New("prover: ECtF generates random number failed")
		}
		printDebugInfoFromBigInt(proverECtF.ectf.randomElementOrEtaInVector, "rho1")
	} else if pStore.countMtAType == 1 {
		proverECtF.ectf.randomElementOrEtaInVector = pStore.eta
		printDebugInfoFromBigInt(pStore.eta, "eta1")
	} else {
		return nil, errors.New("prover: CountMtA type fails")
	}

	p, err := rand.Prime(c.config.rand(), 1024)
	if err != nil {
		return nil, errors.New("prover: Paillier cryptosystem generates prime number p failed")
	}

	q, err := rand.Prime(c.config.rand(), 1024)
	if err != nil {
		return nil, errors.New("prover: Paillier cryptosystem generates prime number q failed")
	}
	proverECtF.mtaPrivateKey = paillier.CreatePrivateKey(p, q)
	params, _ := ka.originalParams.(*nistParameters)

	if sendX {
		proverECtF.ectf.publicElementInVector = new(big.Int).SetBytes(params.SharedKey(ka.serverPublicKey))
		pStore.pxECParam = new(big.Int).SetBytes(params.SharedKey(ka.serverPublicKey))
		printDebugInfoFromBigInt(pStore.pxECParam, "x_1")
		pStore.countMtAType = 0
	} else {
		proverECtF.ectf.publicElementInVector = new(big.Int).SetBytes(params.SharedKeyInY(ka.serverPublicKey))
		pStore.pyECParam = new(big.Int).SetBytes(params.SharedKeyInY(ka.serverPublicKey))
		printDebugInfoFromBigInt(pStore.pyECParam, "y_1")
		pStore.countMtAType = 1
	}
	// IMPORTANT additive inverse
	negPublicElement := new(big.Int).Neg(proverECtF.ectf.publicElementInVector)
	proverECtF.ectf.publicElementInVector = new(big.Int).Mod(negPublicElement, pStore.p)

	encryptNegPublicElementInVector, err := proverECtF.mtaPrivateKey.Encrypt(proverECtF.ectf.publicElementInVector, c.config.rand())
	encryptRandomElementOrEtaInVector, err := proverECtF.mtaPrivateKey.Encrypt(proverECtF.ectf.randomElementOrEtaInVector, c.config.rand())
	pMsg := new(proverSendMsg)
	pMsg.CipherNegPublicElementInVector = encryptNegPublicElementInVector.C.Bytes()
	pMsg.CipherRandomElementInVector = encryptRandomElementOrEtaInVector.C.Bytes()
	pMsg.MtAPublicKey = proverECtF.mtaPrivateKey.PublicKey.N.Bytes()

	pMsg.MessageType = ProverMtAMessage
	return pMsg, err
}

func (c *Conn) constructProverDeltaMessage(pStore *proverLocalStorage) *proverSendMsg {
	pMsg := new(proverSendMsg)
	pMsg.MessageType = ProverDeltaMessage
	pMsg.Delta = pStore.delta.Bytes()
	return pMsg
}

func (c *Conn) constructProverMtAMessageTypeScalar(proverECtF *ProverECtF, pStore *proverLocalStorage) (*proverSendMsg, error) {
	proverECtF.clearMtA()

	p, err := rand.Prime(c.config.rand(), 1024)
	if err != nil {
		return nil, errors.New("prover: Paillier cryptosystem generates prime number p failed")
	}

	q, err := rand.Prime(c.config.rand(), 1024)
	if err != nil {
		return nil, errors.New("prover: Paillier cryptosystem generates prime number q failed")
	}
	proverECtF.mtaPrivateKey = paillier.CreatePrivateKey(p, q)
	proverECtF.ectf.scalarElement = pStore.lambda
	pStore.countMtAType = 2

	encryptScalarElement, err := proverECtF.mtaPrivateKey.Encrypt(proverECtF.ectf.scalarElement, c.config.rand())
	pMsg := new(proverSendMsg)
	pMsg.CipherScalarElement = encryptScalarElement.C.Bytes()
	pMsg.MtAPublicKey = proverECtF.mtaPrivateKey.PublicKey.N.Bytes()
	pMsg.MessageType = ProverMtAMessageScalar
	return pMsg, err
}

//TODO: runPreMasterKeySharing AND runSendS1 ONLY FOR DEBUGGING, NEED TO BE REMOVED
//func (c *Conn) runPreMasterKeySharing(verifierAddress string, localCACertPath string, ka keyAgreement) *verifierResponseMsg {
//
//	if c.config.ProverInternalConfig == nil {
//		c.config.ProverInternalConfig = setDefaultProverConfig(localCACertPath, false, verifierAddress)
//	}
//
//	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
//	if err != nil {
//		log.Fatalf("prover: dial: %s", err)
//	}
//	defer conn.Close()
//	log.Println("prover: connected to: ", conn.RemoteAddr())
//	pMsg := &proverSendMsg{MessageType: SharedPreMasterKey}
//	encoder := json.NewEncoder(conn)
//	encoder.Encode(pMsg)
//	var vRespMsg *verifierResponseMsg
//	decoder := json.NewDecoder(conn)
//	decoder.Decode(&vRespMsg)
//	if ecdheka, ok := ka.(*ecdheKeyAgreement); ok {
//		ecdheka.preMasterSecret = vRespMsg.SharePreMasterKey
//	}
//	log.Print("prover: PV premaster sharing successfully finished")
//	return vRespMsg
//}

//func (c *Conn) runSendS1(verifierAddress string, pStore *proverLocalStorage) {
//	var jMess = new(proverSendMsg)
//	jMess.MessageType = Test
//	jMess.S = pStore.s.Bytes()
//	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
//	if err != nil {
//		log.Fatalf("prover: dial: %s", err)
//	}
//	defer conn.Close()
//	log.Println("prover: connected to: ", conn.RemoteAddr())
//	encoder := json.NewEncoder(conn)
//	err = encoder.Encode(jMess)
//	if err != nil {
//		fmt.Println(err)
//		fmt.Println("end...")
//	}
//}

func (c *Conn) run3PHandshakePRF2PC(verifierAddress string) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = Start3PHandshakePRF2PC
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("end...")
	}
	defer conn.Close()
}

func (c *Conn) runClientFinished2PC(verifierAddress string) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = StartClientFinished2PC
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("end...")
	}
	defer conn.Close()
}

func (c *Conn) runServerFinished2PC(verifierAddress string) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = StartServerFinished2PC
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("end...")
	}
	defer conn.Close()
}

func (c *Conn) run2PCHMacForApplicationData(verifierAddress string) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = StartApp2PCHMac
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("end...")
	}
	defer conn.Close()
}

func (c *Conn) run2PCHMacForServerHMac(verifierAddress string) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = StartSer2PCHMac
	fmt.Println("server mac diag...")
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("end...")
	}
	defer conn.Close()
}

func (c *Conn) commitToVerifier(verifierAddress string, config *Config) *verifierResponseMsg {

	var jMess = new(proverSendMsg)
	jMess.MessageType = ProverCommitMessage
	jMess.CommitCipherQuery = config.commitRecord.cipherQuery
	jMess.CommitCipherResp = config.commitRecord.cipherResponse
	jMess.CommitRKeyMac = config.hs2PCProverOutput.rKeyMac
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("commitment failed")
	}
	var vRespMsg *verifierResponseMsg
	decoder := json.NewDecoder(conn)
	decoder.Decode(&vRespMsg)
	log.Print("prover: PV premaster sharing successfully finished")
	return vRespMsg
}

func (c *Conn) runZKSNARKVerify(verifierAddress string, BiMinus, ivAES, padding []byte) {
	var jMess = new(proverSendMsg)
	jMess.MessageType = ZKSNARKVerify
	jMess.BiMinus = BiMinus
	jMess.IVForLast3Blocks = ivAES
	jMess.Padding = padding
	log.Println("prover: zksnark verify message sent...")
	conn, err := Dial("tcp", verifierAddress, c.config.ProverInternalConfig)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())
	encoder := json.NewEncoder(conn)
	err = encoder.Encode(jMess)
	if err != nil {
		fmt.Println(err)
		fmt.Println("verify message failed")
	}
	defer conn.Close()
}
