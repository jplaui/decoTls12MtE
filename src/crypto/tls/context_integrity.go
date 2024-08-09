package tls

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"regexp"
)

type serverJsonData struct {
	Price string `json:"price"`
}

type contextIntegrity struct {
	payload                    []byte
	payloadLen                 int
	paddingLen                 int
	idxKeyValuePair            []int
	idxValue                   []int
	macSize                    int
	keyValuePair               string
	value                      string
	seqAndHeaderLen            int
	keyStartIdxInSingleBlock   int
	keyStopIdxInSingleBlock    int
	redactedPayloadStartBlkIdx int
	//redactedPayloadStopBlkIdx  int
}

func (ctxi *contextIntegrity) parserJsonData(matcherKeyValuePair *regexp.Regexp, matcherValue *regexp.Regexp) error {
	jsonDataByte := ctxi.payload[:ctxi.payloadLen-ctxi.paddingLen-ctxi.macSize]
	var jsonData serverJsonData
	json.Unmarshal(jsonDataByte, &jsonData)
	if jsonData.Price != "" {
		ctxi.value = jsonData.Price
		ctxi.keyValuePair = matcherKeyValuePair.FindString(string(jsonDataByte))
		ctxi.idxKeyValuePair = matcherKeyValuePair.FindStringIndex(string(jsonDataByte))
		matcherKeyValuePair.FindStringIndex(ctxi.keyValuePair)
		ctxi.idxValue = matcherValue.FindStringIndex(ctxi.keyValuePair)

		// key value pair within first block of hash payload
		ctxi.redactedPayloadStartBlkIdx = (ctxi.idxKeyValuePair[0] + ctxi.seqAndHeaderLen) / sha256.BlockSize

		//TODO: support reveal mode
		//ctxi.redactedPayloadStopBlkIdx = (ctxi.idxKeyValuePair[1] + ctxi.seqAndHeaderLen) / 64
		//ctxi.redactedPayloadStopBlkIdx = (ctxi.payloadLen+ctxi.seqAndHeaderLen)/64 + 1

		if ctxi.idxKeyValuePair[0] < 64-ctxi.seqAndHeaderLen {
			ctxi.keyStartIdxInSingleBlock = ctxi.idxKeyValuePair[0] + ctxi.seqAndHeaderLen
			return errors.New("prover: redacting mode doesn't allow" + ctxi.keyValuePair + "in first sha 256 block")
		} else {
			ctxi.keyStartIdxInSingleBlock = (ctxi.idxKeyValuePair[0] - (64 - ctxi.seqAndHeaderLen)) % sha256.BlockSize
		}
		ctxi.keyStopIdxInSingleBlock = ctxi.keyStartIdxInSingleBlock + ctxi.idxKeyValuePair[1] - ctxi.idxKeyValuePair[0]
		return nil
	} else {
		return errors.New("prover: server json data doesn't contain price information")
	}
}
