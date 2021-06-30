package elliptic

import "testing"

func TestOnCurve(t *testing.T) {
	if !Secp256k1.IsOnCurve(Secp256k1.Gx, Secp256k1.Gy) {
		t.Errorf("FAIL")
	}
}
