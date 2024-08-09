package tls

import (
	"crypto/rand"
	"github.com/didiercrunch/paillier"
	"io"
	"math/big"
)

type ECtF struct {
	randomElementOrEtaInVector *big.Int
	publicElementInVector      *big.Int
	scalarElement              *big.Int
	scalarRandom               *big.Int
	s                          *big.Int
}

type ProverECtF struct {
	ectf          *ECtF
	mtaPrivateKey *paillier.PrivateKey
}

type VerifierECtF struct {
	ectf            *ECtF
	mtaPublicKey    *paillier.PublicKey
	mtaRandomSecret *big.Int
	mtaEncryptData  *big.Int
}

func generateRandomNumber(p *big.Int, random io.Reader) (*big.Int, error) {
	r, err := rand.Int(random, p)
	if err != nil {
		return nil, err
	}
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(r) == 0 {
		return generateRandomNumber(p, random)
	}
	return r, nil
}

func (ectf *ECtF) GenerateRandomElementInVector(p *big.Int, random io.Reader) error {
	randomElementInVector, err := generateRandomNumber(p, random)
	if err != nil {
		return err
	}
	ectf.randomElementOrEtaInVector = randomElementInVector
	return nil
}

func (ectf *ECtF) GenerateRandomScalarElement(p *big.Int, random io.Reader) error {
	randomScalarElement, err := generateRandomNumber(p, random)
	if err != nil {
		return err
	}
	ectf.scalarRandom = randomScalarElement
	return nil
}

func (verifierECtF *VerifierECtF) GenerateMtAVerifierSecreteBeta(p *big.Int, random io.Reader) error {
	var err error
	verifierECtF.mtaRandomSecret, err = generateRandomNumber(p, random)
	if err != nil {
		return err
	}
	return nil
}

func (verifierECtF *VerifierECtF) VerifierMtAEncrypt(pMsg *proverSendMsg) error {
	cipherRandomElementInVector := new(big.Int).SetBytes(pMsg.CipherRandomElementInVector)
	cipherNegPublicElementInVector := new(big.Int).SetBytes(pMsg.CipherNegPublicElementInVector)
	nSquare := verifierECtF.mtaPublicKey.GetNSquare()
	left := new(big.Int).Exp(cipherNegPublicElementInVector, verifierECtF.ectf.randomElementOrEtaInVector, nSquare)
	right := new(big.Int).Exp(cipherRandomElementInVector, verifierECtF.ectf.publicElementInVector, nSquare)
	result := new(big.Int).Mul(left, right)
	var encryptRandomSecret *paillier.Cypher
	var err error
	if encryptRandomSecret, err = verifierECtF.mtaPublicKey.Encrypt(verifierECtF.mtaRandomSecret, rand.Reader); err != nil {
		return err
	}
	result = new(big.Int).Mul(result, encryptRandomSecret.C)
	result = new(big.Int).Mod(result, nSquare)
	verifierECtF.mtaEncryptData = result
	return nil
}

func (verifierECtF *VerifierECtF) VerifierMtAScalarEncrypt(pMsg *proverSendMsg) error {
	cipherScalarElement := new(big.Int).SetBytes(pMsg.CipherScalarElement)
	nSquare := verifierECtF.mtaPublicKey.GetNSquare()

	//exp := new(big.Int).Exp(cipherScalarElement, verifierECtF.ectf.scalarRandom, nSquare)

	exp := new(big.Int).Exp(cipherScalarElement, verifierECtF.ectf.scalarElement, nSquare)
	var encryptRandomSecret *paillier.Cypher
	var err error
	if encryptRandomSecret, err = verifierECtF.mtaPublicKey.Encrypt(verifierECtF.mtaRandomSecret, rand.Reader); err != nil {
		return err
	}
	result := new(big.Int).Mul(exp, encryptRandomSecret.C)
	result = new(big.Int).Mod(result, nSquare)
	//verifierECtF.mtaAlphaOrLambda
	verifierECtF.mtaEncryptData = result
	return nil
}

func (verifierECtF *VerifierECtF) VerifierPostMtAEncrypt(vStore *verifierLocalStorage) {
	x := vStore.vxECParam
	y := vStore.vyECParam
	var rhoOrEta *big.Int
	var iDelta *big.Int
	if vStore.countMtAType == 0 {
		rhoOrEta = vStore.rho
		iDelta = new(big.Int).Mul(x, rhoOrEta)
	} else {
		rhoOrEta = vStore.eta
		iDelta = new(big.Int).Mul(y, rhoOrEta)
	}

	randomSecret := verifierECtF.mtaRandomSecret
	randomSecret = new(big.Int).Neg(randomSecret)

	verifierECtF.mtaRandomSecret = new(big.Int).Mod(randomSecret, vStore.p)
	printDebugInfoFromBigInt(verifierECtF.mtaRandomSecret, "random secrete 2 after p mod 2")
	if vStore.countMtAType == 0 {
		delta := new(big.Int).Add(iDelta, verifierECtF.mtaRandomSecret)
		vStore.delta = new(big.Int).Mod(delta, vStore.p)
		printDebugInfoFromBigInt(vStore.delta, "delta2")
	} else {
		lambda := new(big.Int).Add(iDelta, verifierECtF.mtaRandomSecret)
		vStore.lambda = new(big.Int).Mod(lambda, vStore.p)
		printDebugInfoFromBigInt(vStore.lambda, "lambda2")
	}
}

func (verifierECtF *VerifierECtF) VerifierPostScalarMtAEncrypt(vStore *verifierLocalStorage) {

	randomSecret := verifierECtF.mtaRandomSecret
	randomSecret = new(big.Int).Neg(randomSecret)
	verifierECtF.mtaRandomSecret = new(big.Int).Mod(randomSecret, vStore.p)
	vStore.gamma = verifierECtF.mtaRandomSecret
	printDebugInfoFromBigInt(vStore.gamma, "gamma2")
}

func etaCalculate(rho *big.Int, delta *big.Int, p *big.Int) *big.Int {
	deltaInv := new(big.Int).ModInverse(delta, p)
	result := new(big.Int).Mul(rho, deltaInv)
	return new(big.Int).Mod(result, p)
}

func shareScreteCalculate(gamma *big.Int, lambda *big.Int, x *big.Int, p *big.Int) *big.Int {
	two := big.NewInt(2)
	double := new(big.Int).Mul(two, gamma)
	square := new(big.Int).Exp(lambda, two, p)
	result := new(big.Int).Add(double, square)
	result = new(big.Int).Sub(result, x)
	result = new(big.Int).Mod(result, p)
	return result
}
func (proverECtF *ProverECtF) clearMtA() {
	proverECtF.ectf = new(ECtF)
	proverECtF.mtaPrivateKey = nil
}

func (verifierECtF *VerifierECtF) clearMtA() {
	verifierECtF.ectf = new(ECtF)
	verifierECtF.mtaPublicKey = nil
	verifierECtF.mtaRandomSecret = nil
	verifierECtF.mtaEncryptData = nil
}
