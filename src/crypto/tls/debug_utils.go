package tls

import (
	"fmt"
	"math/big"
)

func printDebugInfoFromByte(b []byte, s string) {
	fmt.Printf("------------------------%s------------------------\n", s)
	fmt.Println(new(big.Int).SetBytes(b))
}

func printDebugInfoFromBigInt(b *big.Int, s string) {
	//fmt.Printf("------------------------%s------------------------\n", s)
	//fmt.Println(b)
}

//func printDebugInfoFromBigInt(b *big.Int, s string) {}
//func printDebugInfoFromByte(b []byte, s string)     {}

func printDebugInfoFromProverSendMsg(pSendMsg *proverSendMsg)             {}
func printDebugInfoFromVerifierResponseMsg(vRespMsg *verifierResponseMsg) {}

//func printDebugInfoFromProverSendMsg(pSendMsg *proverSendMsg) {
//	pSendMsgByteFormat, err := json.Marshal(&pSendMsg)
//	fmt.Println(string(pSendMsgByteFormat))
//	if err != nil {
//		log.Printf("verifier: json corrupt %s", err)
//	}
//}
//
//func printDebugInfoFromVerifierResponseMsg(vRespMsg *verifierResponseMsg) {
//	vRespMsgByte, err := json.Marshal(vRespMsg)
//	fmt.Println(string(vRespMsgByte))
//	if err != nil {
//		log.Printf("verifier: verifier's response data format not corrupted: %s", err)
//	}
//}

func printDebugInfoFromString(data string, label string) {
	fmt.Printf("------------------------%s-----------------------\n", label)
	fmt.Println(data)
}

func debugPrint(data []byte, length int, label string) {
	printDebugInfoFromString(fillStringInputFormat(new(big.Int).SetBytes(data).Text(16), length*2), label)
}
