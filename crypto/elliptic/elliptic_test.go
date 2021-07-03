package elliptic

import (
	"math/big"
	"os"
	"testing"
)

var (
	curve          *CurveParams
	x1, y1, x2, y2 *big.Int
)

func TestMain(m *testing.M) {
	P := big.NewInt(277)
	A := big.NewInt(-3)
	B := big.NewInt(7)

	curve = new(CurveParams)
	curve.P = new(big.Int).Set(P)
	curve.A = new(big.Int).Set(A)
	curve.B = new(big.Int).Set(B)

	x1, x2 = big.NewInt(1), big.NewInt(10)
	y1, y2 = curve.polynomial(x1), curve.polynomial(x2)
	y1.ModSqrt(y1, P)
	y1.Mod(y1, P)
	y2.ModSqrt(y2, P)
	y2.Mod(y2, P)

	os.Exit(m.Run())
}

func TestOnCurve(t *testing.T) {
	if !Secp256k1.IsOnCurve(Secp256k1.Gx, Secp256k1.Gy) {
		t.Errorf("FAIL")
	}
}

func TestOffCurve(t *testing.T) {
	x, y := big.NewInt(1), big.NewInt(1)
	if Secp256k1.IsOnCurve(x, y) {
		t.Errorf("FAIL")
	}
}

func TestAdd(t *testing.T) {
	x, y := curve.Add(x1, y1, x2, y2)

	if x.Int64() != 244 || y.Int64() != 203 {
		t.Errorf("FAIL")
	}
}

func TestScalarMult(t *testing.T) {
	k := big.NewInt(5)
	x, y := curve.ScalarMult(x1, y1, k)

	if x.Int64() != 94 || y.Int64() != 161 {
		t.Errorf("FAIL")
	}

}

func TestMarshal(t *testing.T) {
	buf := Marshal(Secp256k1, Secp256k1.Gx, Secp256k1.Gy)
	if len(buf) != 65 {
		t.Errorf("FAIL")
	}

	x, y := Unmarshal(Secp256k1, buf)
	if x.Cmp(Secp256k1.Gx) != 0 || y.Cmp(Secp256k1.Gy) != 0 {
		t.Errorf("FAIL")
	}
}

func TestMarshalCompressed(t *testing.T) {
	buf := MarshalCompressed(Secp256k1, Secp256k1.Gx, Secp256k1.Gy)
	if len(buf) != 33 {
		t.Errorf("FAIL")
	}

	x, y := Unmarshal(Secp256k1, buf)
	if x.Cmp(Secp256k1.Gx) != 0 || y.Cmp(Secp256k1.Gy) != 0 {
		t.Errorf("FAIL")
	}
}
