package tls

import (
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
	"testing"
)

func b(i int) *big.Int {
	return big.NewInt(int64(i))
}
func isValidRandomNumber(r *big.Int, p *big.Int) bool {
	zero := big.NewInt(0)
	one := big.NewInt(1)
	if zero.Cmp(r) == 0 || one.Cmp(r) == 0 || r.Cmp(p) >= 0 {
		return false
	}
	return true

}

func TestMytest(t *testing.T) {
	ectf := new(ECtF)
	p := elliptic.P384().Params().P
	for i := 0; i < 100; i++ {
		err := ectf.GenerateRandomElementInVector(p, rand.Reader)
		if err != nil {
			t.Error(err)
			return
		}
		if !isValidRandomNumber(ectf.randomElementOrEtaInVector, p) {
			t.Fail()
		}
	}
}
