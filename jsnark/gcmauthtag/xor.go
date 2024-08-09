// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcmauthtag

import "fmt"

// xorBytes xors the bytes in a and b. The destination should have enough
// space, otherwise xorBytes will panic. Returns the number of bytes xor'd.
func xorBytes(dst, a, b []byte) int {
	n := len(a)

	// b in ou case always 16 bytes long
	// n can be lower if plaintext shorter than 16 bytes
	if len(b) < n {
		n = len(b)
	}
	// return no xor if plaintext a.length == 0
	if n == 0 {
		return 0
	}

	_ = dst[n-1]
	xorBytesSSE2(&dst[0], &a[0], &b[0], n) // amd64 must have SSE2
	return n
}

func xorWords(dst, a, b []byte) {
	fmt.Println("xorWords calling xorBytes")
	xorBytes(dst, a, b)
}

//go:noescape
func xorBytesSSE2(dst, a, b *byte, n int)
