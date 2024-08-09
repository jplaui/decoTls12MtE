package main

import (
	"crypto/x509"
	"flag"
	"gitlab.lrz.de/tum-ei-esi/group-identity/deco-oracle/src/crypto/tls"
	"io/ioutil"
	"log"
)

func main() {
	//rand.Seed(20)
	addressPtr := flag.String("address", "127.0.0.1", "IP address")
	portPtr := flag.String("port", "8080", "Port number")
	priKeyLocPtr := flag.String("priv key location", "../certs/verifier.pem",
		"private key location")
	pubKeyLocPtr := flag.String("pub key location", "../certs/verifier.key",
		"public key location")
	caPathPtr := flag.String("path", "../certs/ca.crt", "CA certification path")
	flag.Parse()
	cert, err := tls.LoadX509KeyPair(*priKeyLocPtr, *pubKeyLocPtr)

	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	caCert, err := ioutil.ReadFile(*caPathPtr)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	decoPathConfig, err := tls.ReadConf("/root/deco-oracle/config.yml")
	if err != nil {
		log.Fatal(err)
	}

	Config := &tls.Config{
		ServerName:               "localhost",
		Certificates:             []tls.Certificate{cert},
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		},
		SessionTicketsDisabled: false,
		Run3PHSProtocol:        false,
		RootCAs:                caCertPool,
		PathConfig:             decoPathConfig,
	}

	tls.RunVerifier(*addressPtr, *portPtr, *caPathPtr, Config)
}
