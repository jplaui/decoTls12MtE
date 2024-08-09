package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
)

func (c *Conn) generateVerifierRandomNumber() (*verifierResponseMsg, error) {
	verifierRepsMsg := &verifierResponseMsg{
		RandomVerifier: make([]byte, 32),
	}

	_, err := io.ReadFull(c.config.rand(), verifierRepsMsg.RandomVerifier)
	if err != nil {
		return nil, errors.New("tls: verifier generates 32 byte random: " + err.Error())
	}
	return verifierRepsMsg, nil
}

func (c *Conn) generateVerifierECParameter(serverKeyAndSig []byte) (ecdheParameters, CurveID, error) {

	if len(serverKeyAndSig) < 4 {
		return nil, 0, errServerKeyExchange
	}
	if serverKeyAndSig[0] != 3 { // named curve
		return nil, 0, errors.New("tls: server selected unsupported curve")
	}
	curveID := CurveID(serverKeyAndSig[1])<<8 | CurveID(serverKeyAndSig[2])
	params, err := generateECDHEParameters(c.config.rand(), curveID)
	if err != nil {
		return nil, 0, err
	}
	return params, curveID, nil
}

func (c *Conn) verifyECPublicKey(pMsg *proverSendMsg, storage *verifierLocalStorage) error {
	cert := storage.cert
	storage.cipherSuite = mutualCipherSuite(c.config.CipherSuites, pMsg.CipherSuite)
	if storage.cipherSuite == nil {
		return errors.New("verifier: unsupported cipher suite from server")
	}
	ka := storage.cipherSuite.ka(storage.TLSVersion)
	err := ka.verifyForwardServerPublicKeyWithSignature(pMsg, storage, cert)
	if err != nil {
		return err
	}
	return nil
}

func (c *Conn) verifyForwardsCertificates(serverCert *[]byte, storage *verifierLocalStorage) error {
	m := new(certificateMsg)
	if !m.unmarshal(*serverCert) {
		return errors.New("certificate corrupted")
	}

	if err := c.verifyForwardServerCertificate(m.certificates); err != nil {
		return err
	}
	storage.cert = c.forwardPeerCertificates[0]
	return nil
}

func (c *Conn) verifyForwardServerCertificate(certificates [][]byte) error {
	certs := make([]*x509.Certificate, len(certificates))
	for i, asn1Data := range certificates {
		cert, err := x509.ParseCertificate(asn1Data)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse certificate from server: " + err.Error())
		}
		certs[i] = cert
	}

	if !c.config.InsecureSkipVerify {
		opts := x509.VerifyOptions{
			Roots:         c.config.RootCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
		}
		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}
		var err error
		c.verifiedChains, err = certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	switch certs[0].PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		break
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: server's certificate contains an unsupported type of public key: %T", certs[0].PublicKey)
	}

	c.forwardPeerCertificates = certs

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.forwardVerifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	return nil
}
