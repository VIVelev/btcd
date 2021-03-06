// Package elliptic implements several standard elliptic curves over prime finite fields
// of the form: y^2 = x^3 + a*x + b (mod p)
package elliptic

import (
	"errors"
	"math/big"
)

type Curve interface {
	// Params returns the parameters for the curve.
	Params() *CurveParams
	// IsOnCurve reports whether the given (x,y) lies on the curve.
	IsOnCurve(x, y *big.Int) bool
	// Add returns the sum of (x1,y1) and (x2,y2)
	Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int)
	// ScalarMult returns k*(x1, y1)
	ScalarMult(x1, y1, k *big.Int) (x, y *big.Int)
	// ScalarBaseMult returns k*G, where G is the base point of the group
	ScalarBaseMult(k *big.Int) (x, y *big.Int)
}

// CurveParams contains the parameters of an elliptic curve and also provides
// a generic implementation of Curve.
type CurveParams struct {
	P       *big.Int // the order of the underlying finite field
	N       *big.Int // the order of the base (generator) point
	A       *big.Int // the constant of the curve equation
	B       *big.Int // the constant of the curve equation
	Gx, Gy  *big.Int // (x,y) of the base point
	BitSize int      // the size of the underlying field
	Name    string   // the canonical name of the curve
}

func (curve *CurveParams) Params() *CurveParams {
	return curve
}

// polynomial returns x^3 + a*x + b (mod p)
func (curve *CurveParams) polynomial(x *big.Int) *big.Int {
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	aX := new(big.Int).Mul(curve.A, x)

	x3.Add(x3, aX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	return x3
}

func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	// y^2 = x^3 + a*x + b
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	return curve.polynomial(x).Cmp(y2) == 0
}

// isPointAtInf tests whether (x,y) is the point at infinity
func isPointAtInf(x, y *big.Int) bool {
	return x.Sign() == 0 && y.Sign() == 0
}

func (curve *CurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	// TODO: What happens when the points (x1,y1) & (x2,y2) are not on the curve?

	x, y = new(big.Int), new(big.Int)

	// handle the special case of additive identity
	if isPointAtInf(x1, y1) {
		x.Set(x2)
		y.Set(y2)
		return
	}
	if isPointAtInf(x2, y2) {
		x.Set(x1)
		y.Set(y1)
		return
	}
	// handle the special case of additive inverse
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) != 0 {
		// return the point at infinity
		x.SetInt64(0)
		y.SetInt64(0)
		return
	}

	// compute the slope
	m := new(big.Int)
	if x1.Cmp(x2) == 0 { // y1 == y2 is guaranteed by the above check
		// m = (3 * x1^2 + a) / (2 * y1)
		m.Mul(x1, x1)
		tmp := new(big.Int).Set(m)
		m.Lsh(m, 1)
		m.Add(m, tmp)
		m.Add(m, curve.A)
		denominator := new(big.Int).Add(y1, y1)
		denominator.ModInverse(denominator, curve.P)
		m.Mul(m, denominator)

	} else {
		// m = (y1 - y2) / (x1 - x2)
		m.Sub(y1, y2)
		denominator := new(big.Int).Sub(x1, x2)
		denominator.ModInverse(denominator, curve.P)
		m.Mul(m, denominator)
	}
	// compute the new points
	// x = (m^2 - x1 - x2) % P
	x.Mul(m, m)
	x.Sub(x, x1)
	x.Sub(x, x2)
	x.Mod(x, curve.P)
	// y = (-(m * (x - x1) + y1)) % P
	y.Sub(x, x1)
	y.Mul(m, y)
	y.Add(y, y1)
	y.Neg(y)
	y.Mod(y, curve.P)

	return
}

func (curve *CurveParams) ScalarMult(x1, y1, k *big.Int) (x, y *big.Int) {
	// Set (x,y) to the additive identity (the point at infinity)
	x = big.NewInt(0)
	y = big.NewInt(0)
	appendX, appendY := new(big.Int).Set(x1), new(big.Int).Set(y1)

	i := 0
	for i < k.BitLen() {
		if k.Bit(i) == 1 {
			x, y = curve.Add(x, y, appendX, appendY)
		}
		appendX, appendY = curve.Add(appendX, appendY, appendX, appendY)
		i += 1
	}
	return
}

func (curve *CurveParams) ScalarBaseMult(k *big.Int) (x, y *big.Int) {
	x, y = curve.ScalarMult(curve.Gx, curve.Gy, k)
	return
}

// Marshal serializes a point (x,y) in a uncompressed format.
func Marshal(curve Curve, x, y *big.Int) []byte {
	byteSize := (curve.Params().BitSize + 7) / 8
	ret := make([]byte, 2*byteSize+1)
	ret[0] = 4
	copy(ret[1:byteSize+1], x.Bytes())
	copy(ret[byteSize+1:], y.Bytes())
	return ret
}

// MarshalCompressed serializes a point (x,y) in a compressed
// SEC format.
func MarshalCompressed(curve Curve, x, y *big.Int) []byte {
	byteSize := (curve.Params().BitSize + 7) / 8
	ret := make([]byte, byteSize+1)
	if y.Bit(0) == 0 {
		ret[0] = 2
	} else {
		ret[0] = 3
	}
	copy(ret[1:], x.Bytes())
	return ret
}

// Unmarshal deserializes a point (x,y)
func Unmarshal(curve Curve, buf []byte) (x, y *big.Int, err error) {
	byteSize := (curve.Params().BitSize + 7) / 8

	// Uncompressed unmarshal.
	if buf[0] == 4 {
		x = new(big.Int).SetBytes(buf[1 : byteSize+1])
		y = new(big.Int).SetBytes(buf[byteSize+1:])
		return
	}

	if buf[0] != 2 && buf[0] != 3 {
		return nil, nil, errors.New("Unmarshal: invalid prefix byte")
	}

	// Compressed unmarshal.
	p := curve.Params().P
	isEven := buf[0] == 2
	x = new(big.Int).SetBytes(buf[1 : byteSize+1])
	// y^2 = x^3 + a*x + b (mod p)
	y = curve.Params().polynomial(x)
	y.ModSqrt(y, p)
	y.Mod(y, p)

	if (y.Bit(0) == 0) == isEven {
		return
	} else {
		y.Sub(p, y)
		return
	}
}
