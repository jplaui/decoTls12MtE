package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"log"
	"net"
	"reflect"

	"gitlab.lrz.de/tum-ei-esi/group-identity/deco-oracle/src/crypto/tls"
)

func main() {
	cert, err := tls.LoadX509KeyPair("../certs/server.pem",
		"../certs/server.key")
	if err != nil {
		log.Fatalf("server: loadkeys: %s", err)
	}

	config := tls.Config{
		CurvePreferences:         []tls.CurveID{tls.CurveP256},
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		MaxVersion:               tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
		},
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
	}

	config.Rand = rand.Reader
	service := "0.0.0.0:8000"
	listener, err := tls.Listen("tcp", service, &config)
	if err != nil {
		log.Fatalf("server: listen: %s", err)
	}
	log.Print("server: listening")
	for {
		conn, err := listener.Accept()
		log.Println(reflect.TypeOf(conn))
		log.Printf("%T", conn)
		if err != nil {
			log.Printf("server: accept: %s", err)
			break
		}
		defer conn.Close()
		log.Printf("server: accepted from %s", conn.RemoteAddr())

		tlscon, ok := conn.(*tls.Conn)
		if ok {
			log.Print("ok=true")
			state := tlscon.ConnectionState()
			for _, v := range state.PeerCertificates {
				log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
			}
		}
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 512)
	for {
		log.Print("server: conn: waiting")

		n, err := conn.Read(buf)
		if err != nil {

			log.Printf("server: conn: read: %s", err)

			break
		}
		log.Printf("server: conn: echo %q\n", string(buf[:n]))
		log.Printf("server read client message of byte size: %d", len(string(buf[:n])))

		message := map[string]interface{}{
			"pair":          "BTCUSDT",
			"data":          "2022.04.27",
			"time":          "12:00:00",
			"volume":        "321654",
			"price":         "38000.2",
			"all time high": "660000.5",
			"24 high":       "396564.3",
			"personal data": map[string]string{
				"age":    "20",
				"income": "1,300,561 Euro",
			},
		}
		bytePresentation, err := json.Marshal(message)
		log.Printf("server message byte size: %d", len(bytePresentation))

		n, err = conn.Write(bytePresentation)

		//n, err = conn.Write(buf[:n])
		//log.Printf("server: conn: wrote %d bytes", n)

		if err != nil {
			log.Printf("server: write: %s", err)
			break
		}
	}
	log.Println("server: conn: closed")
}
