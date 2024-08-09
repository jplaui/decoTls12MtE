package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"gitlab.lrz.de/tum-ei-esi/group-identity/deco-oracle/src/crypto/tls"
	"io/ioutil"
	"log"
	"time"
)

func main() {
	//rand.Seed(20)
	saddressPtr := flag.String("SeverAddress", "127.0.0.1", "IP address")
	sportPtr := flag.String("ServerPort", "8000", "Port number")
	vaddressPtr := flag.String("VerifierAddress", "127.0.0.1", "IP address")
	vportPtr := flag.String("VerifierPort", "8080", "Port number")
	caPathPtr := flag.String("path", "../certs/ca.crt", "CA certification path")
	flag.Parse()

	caCert, err := ioutil.ReadFile(*caPathPtr)
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	verifierHttpUrl := *vaddressPtr + ":" + *vportPtr

	// uncomment following lines if prover doesn't want to rely on internal default TLS config for P/C communication
	//proverInternalConfig := &tls.Config{
	//	RootCAs:                  caCertPool,
	//	CurvePreferences:         []tls.CurveID{tls.CurveP384},
	//	PreferServerCipherSuites: true,
	//	MinVersion:               tls.VersionTLS12,
	//	MaxVersion:               tls.VersionTLS12,
	//	CipherSuites: []uint16{
	//		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	//	},
	//	ClientSessionCache:     tls.NewLRUClientSessionCache(32),
	//	Run3PHSProtocol:        false,
	//	LocalCACertificatePath: *caPathPtr,
	//Filepath:      "/root/deco-oracle/src/crypto/tls",
	//}

	decoPathConfig, err := tls.ReadConf("/root/deco-oracle/config.yml")
	if err != nil {
		log.Fatal(err)
	}

	config := &tls.Config{
		RootCAs:                  caCertPool,
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		},
		ClientSessionCache: tls.NewLRUClientSessionCache(32),
		//If P/V communication is needed, set true here
		Run3PHSProtocol:        true,
		LocalCACertificatePath: *caPathPtr,
		VerifierHttpUrl:        verifierHttpUrl,
		PathConfig:             decoPathConfig,
		//ProverInternalConfig:   proverInternalConfig,
	}

	RunProver(*saddressPtr, *sportPtr, config)
}

func RunProver(severIpAddr string, serverPort string, config *tls.Config) {
	start := time.Now()
	conn, err := tls.Dial("tcp", severIpAddr+":"+serverPort, config)
	if err != nil {
		log.Fatalf("prover: dial: %s", err)
	}
	elapsed := time.Since(start)
	log.Printf("prover: total andshake took %s", elapsed)
	log.Println("==============================================================")
	defer conn.Close()
	log.Println("prover: connected to: ", conn.RemoteAddr())

	//TODO: depends on what data to be sent
	message := map[string]interface{}{
		"hello": "world",
		"life":  42,
		"embedded": map[string]string{
			"yes": "of course!",
		},
	}
	byteRepresentation, err := json.Marshal(message)
	n, err := conn.Write(byteRepresentation)
	if err != nil {
		log.Fatalf("prover: write: %s", err)
	}
	reply := make([]byte, 256)
	n, err = conn.Read(reply)
	log.Printf("prover: read %q (%d bytes)", string(reply[:n]), n)
}
