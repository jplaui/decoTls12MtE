package gcmauthtag_test

import (
	f "gcmauthtag"
	"testing"
)

func TestAuthGCM(t *testing.T) {

	// AES GCM parameters used to generate input ciphers:
	// key: "7fddb57453c241d03efbed3ac44e371c"
	// none: "ee283a3fc75575e33efd4887"
	// additional data: ""
	// plaintext: "d5de42b461646c255c87bd2962d3b9a2"

	// expected result: cipherPlaintext||tag: "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"

	tagMaskCipher := "598d3ea40503b2563c8843964ff8125b"
	plaintextCipher := "2ccda4a5415cb91e135c2a0f78c9b2fd"
	galoisKexCipher := "122204f9d2a456649d2bb1f744c939d9"
	lengthPlaintext := 16
	lengthAdditionalData := 0

	expectedResult := "2ccda4a5415cb91e135c2a0f78c9b2fdb36d1df9b9d5e596f83e8b7f52971cb3"

	tag := f.AuthGCM(tagMaskCipher, plaintextCipher, galoisKexCipher, lengthPlaintext, lengthAdditionalData)

	// fmt.Println("final tag:", tag)

	if tag != expectedResult {
		t.Fatal("Tag calculation failed.")
	}
}
