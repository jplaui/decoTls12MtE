package tls

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"github.com/didiercrunch/paillier"
	"log"
	"math/big"
)

const (
	ProverCommSetupMessage           byte = 1
	ProverMtAMessage                 byte = 2
	ProverMtAMessageScalar           byte = 3
	ProverDeltaMessage               byte = 4
	VerifierCommSetupResponseMessage byte = 5
	VerifierMtAResponseMessage       byte = 6
	VerifierDeltaResponseMessage     byte = 7
	VerifierMtAScalarResponseMessage byte = 8
	Test                             byte = 9
	SharedPreMasterKey               byte = 10
	StartClientFinished2PC           byte = 11
	StartServerFinished2PC           byte = 12
	StartApp2PCHMac                  byte = 13
	Start3PHandshakePRF2PC           byte = 14
	StartSer2PCHMac                  byte = 15
	ProverCommitMessage              byte = 16
	VerifierMacKeyMessage            byte = 17
	ZKSNARKVerify                    byte = 18
)

type proverSendMsg struct {
	// communication setup message
	MessageType           byte
	CipherSuite           uint16
	TLSVersion            uint16
	RandomServer          []byte
	RandomProver          []byte
	ServerCertificate     []byte
	ServerKeyAndSigParams []byte
	// MtA message (vector)
	CipherNegPublicElementInVector []byte
	CipherRandomElementInVector    []byte
	MtAPublicKey                   []byte
	// delta message
	Delta []byte

	//Gamma message
	Gamma []byte

	// MtA message (scalar)
	CipherScalarElement []byte

	// commit message
	CommitCipherQuery []byte
	CommitCipherResp  []byte
	CommitRKeyMac     []byte

	//zksnark in/out
	BiMinus []byte

	IVForLast3Blocks []byte
	Padding          []byte

	// test
	S []byte
}

type verifierResponseMsg struct {
	// communication setup message
	MessageType      byte
	VerifierECPubKey []byte
	RandomVerifier   []byte

	// MtA message
	CipherTextMtAVerifier []byte

	// Delta message []byte
	Delta []byte

	// Gamma message
	Gamma []byte

	//test
	SharePreMasterKey []byte

	XorClientMac []byte
	XorServerMac []byte

	rClientMac []byte
	rServerMac []byte
}

type verifierLocalStorage struct {
	cipherSuite      *cipherSuite
	TLSVersion       uint16
	RandomServer     []byte
	RandomProver     []byte
	RandomVerifier   []byte
	ServerKey        []byte
	ServerSigParams  []byte
	verifierECPubKey []byte
	vxECParam        *big.Int
	vyECParam        *big.Int
	cert             *x509.Certificate
	verifierECtF     *VerifierECtF
	curveID          CurveID
	countMtAType     int
	rho              *big.Int
	eta              *big.Int
	delta            *big.Int
	lambda           *big.Int
	gamma            *big.Int
	p                *big.Int
	s                *big.Int
	ecdheParams      ecdheParameters

	//test
	keyShare *big.Int

	//commit
	cipherQuery    []byte
	cipherResponse []byte
	rKeyMac        []byte

	//2PC
	hs2PCOut *handShake2PCVerifierOutput
}

type proverLocalStorage struct {
	proverECtF *ProverECtF
	curveID    CurveID
	// xp in Zp
	pxECParam *big.Int
	// yp in Zp
	pyECParam    *big.Int
	rho          *big.Int
	eta          *big.Int
	delta        *big.Int
	lambda       *big.Int
	gamma        *big.Int
	p            *big.Int
	s            *big.Int
	countMtAType int
}

type commitment struct {
	cipherQuery    []uint8
	cipherResponse []uint8
	rKeyMAC        []uint8
}

type verifierMessageHandler interface {
	Set(*proverSendMsg, *verifierResponseMsg, *verifierLocalStorage)
	Get() (*proverSendMsg, *verifierResponseMsg, *verifierLocalStorage)
	handle(c *Conn) (*verifierResponseMsg, *verifierLocalStorage)
}

type verifierKeyExchangeHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	vLocalStorage *verifierLocalStorage
}

type verifierMtAProverHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	vLocalStorage *verifierLocalStorage
}

type verifierMtAScalarHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	vLocalStorage *verifierLocalStorage
}

type verifierDeltaHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	vLocalStorage *verifierLocalStorage
}

type proverMessageHandler interface {
	Set(*proverSendMsg, *verifierResponseMsg, *proverLocalStorage)
	Get() (*proverSendMsg, *verifierResponseMsg, *proverLocalStorage)
	handle(*proverSendMsg, *verifierResponseMsg) *proverLocalStorage
}

type proverKeyExchangeHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	pLocalStorage *proverLocalStorage
}

type proverMtAHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	pLocalStorage *proverLocalStorage
}

type proverMtAScalarHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	pLocalStorage *proverLocalStorage
}

type proverDeltaHandler struct {
	pSendMsg      *proverSendMsg
	vRespMsg      *verifierResponseMsg
	pLocalStorage *proverLocalStorage
}

func (kxHandler *verifierKeyExchangeHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	kxHandler.pSendMsg = pMsg
	kxHandler.vRespMsg = vMsg
	kxHandler.vLocalStorage = vStore
}

func (kxHandler *verifierKeyExchangeHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	return kxHandler.pSendMsg, kxHandler.vRespMsg, kxHandler.vLocalStorage
}

func (kxHandler *verifierKeyExchangeHandler) handle(tlsConn *Conn) (*verifierResponseMsg, *verifierLocalStorage) {
	var err error
	if err = tlsConn.verifyForwardsCertificates(&kxHandler.pSendMsg.ServerCertificate, kxHandler.vLocalStorage); err != nil {
		log.Printf("verifier: server certificates are invalid: %s", err)
	}

	if kxHandler.vRespMsg, err = tlsConn.generateVerifierRandomNumber(); err != nil {
		log.Printf("verifier: generated Random nonce failed %s", err)
	}

	verifierECDHEParameter, curveID, err := tlsConn.generateVerifierECParameter(kxHandler.pSendMsg.ServerKeyAndSigParams)
	if err != nil {
		log.Printf("verifier generated Random nonce failed %s", err)
	}

	kxHandler.vRespMsg.VerifierECPubKey = verifierECDHEParameter.PublicKey()
	kxHandler.vLocalStorage.curveID = curveID
	kxHandler.vLocalStorage.ecdheParams = verifierECDHEParameter
	kxHandler.vLocalStorage.constructVerifierLocalStorage(kxHandler.pSendMsg, kxHandler.vRespMsg)
	if err = tlsConn.verifyECPublicKey(kxHandler.pSendMsg, kxHandler.vLocalStorage); err != nil {
		log.Printf("verifier: forwarded server EC PublicKey corrupted %s", err)
	}
	kxHandler.vRespMsg.MessageType = VerifierCommSetupResponseMessage
	return kxHandler.vRespMsg, kxHandler.vLocalStorage
}

func (mtaHandler *verifierMtAProverHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.vLocalStorage = vStore
}

func (mtaHandler *verifierMtAProverHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *verifierMtAProverHandler) handle(tlsConn *Conn) (*verifierResponseMsg, *verifierLocalStorage) {
	//var err error
	mtaHandler.vRespMsg.MessageType = VerifierMtAResponseMessage
	if mtaHandler.vLocalStorage.verifierECtF == nil {
		mtaHandler.vLocalStorage.verifierECtF = new(VerifierECtF)
		mtaHandler.vLocalStorage.verifierECtF.ectf = new(ECtF)
	} else {
		mtaHandler.vLocalStorage.verifierECtF.clearMtA()
	}

	mtaHandler.vLocalStorage.verifierECtF.mtaPublicKey = new(paillier.PublicKey)
	//
	vECtF := mtaHandler.vLocalStorage.verifierECtF
	vECtF.mtaPublicKey.N = new(big.Int).SetBytes(mtaHandler.pSendMsg.MtAPublicKey)

	curve, _ := curveForCurveID(mtaHandler.vLocalStorage.curveID)

	if mtaHandler.vLocalStorage.vxECParam == nil || mtaHandler.vLocalStorage.vyECParam == nil {
		ecdheParams := mtaHandler.vLocalStorage.ecdheParams
		mtaHandler.vLocalStorage.vxECParam = new(big.Int).SetBytes(ecdheParams.SharedKey(mtaHandler.vLocalStorage.ServerKey))
		mtaHandler.vLocalStorage.vyECParam = new(big.Int).SetBytes(ecdheParams.SharedKeyInY(mtaHandler.vLocalStorage.ServerKey))
		mtaHandler.vLocalStorage.p = curve.Params().P
	}

	if mtaHandler.vLocalStorage.countMtAType == 0 {
		err := vECtF.ectf.GenerateRandomElementInVector(curve.Params().P, rand.Reader)
		if err != nil {
			log.Printf("verifier: MtA random random element generation failed  %s", err)
			return nil, nil
		}
		printDebugInfoFromBigInt(vECtF.ectf.randomElementOrEtaInVector, "rho2")
		vECtF.ectf.publicElementInVector = mtaHandler.vLocalStorage.vxECParam
		printDebugInfoFromBigInt(vECtF.ectf.publicElementInVector, "x2")
		mtaHandler.vLocalStorage.rho = vECtF.ectf.randomElementOrEtaInVector
	} else if mtaHandler.vLocalStorage.countMtAType == 1 {
		vECtF.ectf.randomElementOrEtaInVector = mtaHandler.vLocalStorage.eta
		vECtF.ectf.publicElementInVector = mtaHandler.vLocalStorage.vyECParam
		printDebugInfoFromBigInt(vECtF.ectf.publicElementInVector, "y2")
		printDebugInfoFromBigInt(mtaHandler.vLocalStorage.eta, "eta2")
	} else {
		log.Printf("verifier: CountMtA number is wrong fails")
		return nil, nil
	}

	if err := vECtF.GenerateMtAVerifierSecreteBeta(curve.Params().P, rand.Reader); err != nil {
		log.Printf("verifier: MtA random beta generation failed %s", err)
	}
	printDebugInfoFromBigInt(vECtF.mtaRandomSecret, " random secrete 2 before p mod ")
	vECtF.VerifierMtAEncrypt(mtaHandler.pSendMsg)
	vECtF.VerifierPostMtAEncrypt(mtaHandler.vLocalStorage)
	mtaHandler.vLocalStorage.countMtAType++
	mtaHandler.vRespMsg.CipherTextMtAVerifier = vECtF.mtaEncryptData.Bytes()

	return mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *verifierDeltaHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.vLocalStorage = vStore
}

func (mtaHandler *verifierDeltaHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *verifierDeltaHandler) handle(tlsConn *Conn) (*verifierResponseMsg, *verifierLocalStorage) {
	mtaHandler.vRespMsg.MessageType = VerifierDeltaResponseMessage
	delta2 := mtaHandler.vLocalStorage.delta
	delta1 := new(big.Int).SetBytes(mtaHandler.pSendMsg.Delta)
	delta := new(big.Int).Add(delta1, delta2)

	mtaHandler.vLocalStorage.delta = new(big.Int).Mod(delta, mtaHandler.vLocalStorage.p)
	mtaHandler.vRespMsg.Delta = delta2.Bytes()

	printDebugInfoFromBigInt(mtaHandler.vLocalStorage.delta, "delta")
	return mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *verifierMtAScalarHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.vLocalStorage = vStore
}

func (mtaHandler *verifierMtAScalarHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *verifierLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *verifierMtAScalarHandler) handle(tlsConn *Conn) (*verifierResponseMsg, *verifierLocalStorage) {
	mtaHandler.vRespMsg.MessageType = VerifierMtAScalarResponseMessage

	mtaHandler.vLocalStorage.verifierECtF.clearMtA()
	mtaHandler.vLocalStorage.verifierECtF.mtaPublicKey = new(paillier.PublicKey)
	vECtF := mtaHandler.vLocalStorage.verifierECtF
	vECtF.mtaPublicKey.N = new(big.Int).SetBytes(mtaHandler.pSendMsg.MtAPublicKey)

	vECtF.ectf.scalarElement = mtaHandler.vLocalStorage.lambda

	vECtF.GenerateMtAVerifierSecreteBeta(mtaHandler.vLocalStorage.p, rand.Reader)
	vECtF.VerifierMtAScalarEncrypt(mtaHandler.pSendMsg)
	vECtF.VerifierPostScalarMtAEncrypt(mtaHandler.vLocalStorage)
	mtaHandler.vLocalStorage.countMtAType++
	mtaHandler.vRespMsg.CipherTextMtAVerifier = vECtF.mtaEncryptData.Bytes()
	return mtaHandler.vRespMsg, mtaHandler.vLocalStorage
}

func (mtaHandler *proverKeyExchangeHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.pLocalStorage = pStore
}

func (mtaHandler *proverKeyExchangeHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.pLocalStorage
}

func (mtaHandler *proverKeyExchangeHandler) handle(*proverSendMsg, *verifierResponseMsg) *proverLocalStorage {
	return nil
}

func (mtaHandler *proverMtAHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.pLocalStorage = pStore
}

func (mtaHandler *proverMtAHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.pLocalStorage
}

func (mtaHandler *proverMtAHandler) handle(pMsg *proverSendMsg, vMsg *verifierResponseMsg) *proverLocalStorage {

	vCipher := new(paillier.Cypher)
	vCipher.C = new(big.Int).SetBytes(vMsg.CipherTextMtAVerifier)
	alphaOrBeta := mtaHandler.pLocalStorage.proverECtF.mtaPrivateKey.Decrypt(vCipher)
	alphaOrBeta = new(big.Int).Mod(alphaOrBeta, mtaHandler.pLocalStorage.p)
	var iDeltaOrLambda *big.Int
	var deltaOrLambda *big.Int
	if mtaHandler.pLocalStorage.countMtAType == 0 {
		mtaHandler.pLocalStorage.rho = mtaHandler.pLocalStorage.proverECtF.ectf.randomElementOrEtaInVector
		iDeltaOrLambda = new(big.Int).Mul(mtaHandler.pLocalStorage.proverECtF.ectf.publicElementInVector, mtaHandler.pLocalStorage.rho)
		iDeltaOrLambda = new(big.Int).Add(iDeltaOrLambda, alphaOrBeta)
		deltaOrLambda = new(big.Int).Mod(iDeltaOrLambda, mtaHandler.pLocalStorage.p)
		mtaHandler.pLocalStorage.delta = deltaOrLambda
		printDebugInfoFromBigInt(alphaOrBeta, "alpha1")
		printDebugInfoFromBigInt(deltaOrLambda, "delta1")
	} else if mtaHandler.pLocalStorage.countMtAType == 1 {
		mtaHandler.pLocalStorage.eta = mtaHandler.pLocalStorage.proverECtF.ectf.randomElementOrEtaInVector
		iDeltaOrLambda = new(big.Int).Mul(mtaHandler.pLocalStorage.proverECtF.ectf.publicElementInVector, mtaHandler.pLocalStorage.eta)
		iDeltaOrLambda = new(big.Int).Add(iDeltaOrLambda, alphaOrBeta)
		deltaOrLambda = new(big.Int).Mod(iDeltaOrLambda, mtaHandler.pLocalStorage.p)
		mtaHandler.pLocalStorage.lambda = deltaOrLambda
		printDebugInfoFromBigInt(alphaOrBeta, "beta1")
		printDebugInfoFromBigInt(deltaOrLambda, "lambda1")
	}

	mtaHandler.pLocalStorage.countMtAType++
	return mtaHandler.pLocalStorage
}

func (mtaHandler *proverDeltaHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.pLocalStorage = pStore
}

func (mtaHandler *proverDeltaHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, vStore *proverLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.pLocalStorage
}

func (mtaHandler *proverDeltaHandler) handle(pMsg *proverSendMsg, vMsg *verifierResponseMsg) *proverLocalStorage {
	vMsg.MessageType = VerifierDeltaResponseMessage
	delta1 := mtaHandler.pLocalStorage.delta
	delta2 := new(big.Int).SetBytes(mtaHandler.vRespMsg.Delta)
	delta := new(big.Int).Add(delta1, delta2)
	mtaHandler.pLocalStorage.delta = new(big.Int).Mod(delta, mtaHandler.pLocalStorage.p)
	printDebugInfoFromBigInt(mtaHandler.pLocalStorage.delta, "delta")
	return mtaHandler.pLocalStorage
}

func (mtaHandler *proverMtAScalarHandler) Set(pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	mtaHandler.pSendMsg = pMsg
	mtaHandler.vRespMsg = vMsg
	mtaHandler.pLocalStorage = pStore
}

func (mtaHandler *proverMtAScalarHandler) Get() (pMsg *proverSendMsg, vMsg *verifierResponseMsg, pStore *proverLocalStorage) {
	return mtaHandler.pSendMsg, mtaHandler.vRespMsg, mtaHandler.pLocalStorage
}

func (mtaHandler *proverMtAScalarHandler) handle(pMsg *proverSendMsg, vMsg *verifierResponseMsg) *proverLocalStorage {

	vCipher := new(paillier.Cypher)
	vCipher.C = new(big.Int).SetBytes(vMsg.CipherTextMtAVerifier)
	gamma := mtaHandler.pLocalStorage.proverECtF.mtaPrivateKey.Decrypt(vCipher)
	gamma = new(big.Int).Mod(gamma, mtaHandler.pLocalStorage.p)
	mtaHandler.pLocalStorage.gamma = gamma
	printDebugInfoFromBigInt(gamma, "gamma1")
	mtaHandler.pLocalStorage.countMtAType++
	return mtaHandler.pLocalStorage
}

func (mtaHandler *proverDeltaHandler) afterTransport() {
	delta := mtaHandler.pLocalStorage.delta
	rho := mtaHandler.pLocalStorage.rho
	p := mtaHandler.pLocalStorage.p

	mtaHandler.pLocalStorage.eta = etaCalculate(rho, delta, p)
}

func (mtaHandler *proverMtAScalarHandler) afterTransport() {
	gamma := mtaHandler.pLocalStorage.gamma
	lambda := mtaHandler.pLocalStorage.lambda
	x := mtaHandler.pLocalStorage.pxECParam
	p := mtaHandler.pLocalStorage.p

	mtaHandler.pLocalStorage.s = shareScreteCalculate(gamma, lambda, x, p)
}

func (mtaHandler *verifierMtAScalarHandler) afterTransport() {
	gamma := mtaHandler.vLocalStorage.gamma
	lambda := mtaHandler.vLocalStorage.lambda
	x := mtaHandler.vLocalStorage.vxECParam
	p := mtaHandler.vLocalStorage.p

	mtaHandler.vLocalStorage.s = shareScreteCalculate(gamma, lambda, x, p)
}

func (mtaHandler *verifierDeltaHandler) afterTransport() {
	delta := mtaHandler.vLocalStorage.delta
	rho := mtaHandler.vLocalStorage.rho
	p := mtaHandler.vLocalStorage.p

	mtaHandler.vLocalStorage.eta = etaCalculate(rho, delta, p)
}

func (msg *proverSendMsg) checkProverSendMsg() error {
	switch msg.MessageType {
	case ProverCommSetupMessage:
		if msg.RandomProver == nil || msg.RandomServer == nil || len(msg.RandomProver) != 32 || len(msg.RandomProver) != 32 {
			return errors.New("Random Nonce corrupted")
		} else if msg.TLSVersion == 0 {
			return errors.New("TLS Version not sent")
		}
	case ProverMtAMessage:
		if msg.CipherRandomElementInVector == nil || msg.CipherNegPublicElementInVector == nil || msg.MtAPublicKey == nil {
			return errors.New("x1, rho1, y1, eta1 or public key shouldn't be null")
		}
	case ProverDeltaMessage:
		if msg.Delta == nil {
			return errors.New("delta shouldn't be null")
		}
	case ProverMtAMessageScalar:
		if msg.CipherScalarElement == nil || msg.MtAPublicKey == nil {
			return errors.New("lamda1, public key shouldn't be null")
		}
	default:
		return errors.New("message type not supported")
	}
	return nil
}

func (msg *verifierResponseMsg) checkVerifierResponseMsg() error {
	switch msg.MessageType {
	case VerifierCommSetupResponseMessage:
		if msg.VerifierECPubKey == nil || msg.RandomVerifier == nil {
			return errors.New("response message not well formatted")
		}
	case VerifierMtAResponseMessage, VerifierMtAScalarResponseMessage:
		if msg.CipherTextMtAVerifier == nil {
			return errors.New("response message cipher text shouldn't be null")
		}
	case VerifierDeltaResponseMessage:
		if msg.Delta == nil {
			return errors.New("delta shouldn't be null")
		}
	default:
		return errors.New("response message type not supported")
	}
	return nil
}

func (vLocalStorage *verifierLocalStorage) constructVerifierLocalStorage(pSendMsg *proverSendMsg, vRespMsg *verifierResponseMsg) {
	vLocalStorage.verifierECPubKey = vRespMsg.VerifierECPubKey
	vLocalStorage.TLSVersion = pSendMsg.TLSVersion
	vLocalStorage.RandomVerifier = vRespMsg.RandomVerifier
	vLocalStorage.RandomProver = pSendMsg.RandomProver
	vLocalStorage.RandomServer = pSendMsg.RandomServer
}

func (vStore *verifierLocalStorage) clearVerifierLocalStorage() {
	vStore.cipherSuite = nil
	vStore.TLSVersion = 0
	vStore.RandomServer = nil
	vStore.RandomProver = nil
	vStore.RandomVerifier = nil
	vStore.ServerKey = nil
	vStore.ServerSigParams = nil
	vStore.verifierECPubKey = nil
	vStore.vxECParam = nil
	vStore.vyECParam = nil
	vStore.cert = nil
	vStore.verifierECtF = nil
	vStore.curveID = 0
	vStore.countMtAType = 0
	vStore.rho = nil
	vStore.eta = nil
	vStore.delta = nil
	vStore.lambda = nil
	vStore.gamma = nil
	vStore.p = nil
	vStore.s = nil
	vStore.ecdheParams = nil

	//test
	vStore.keyShare = nil
}
