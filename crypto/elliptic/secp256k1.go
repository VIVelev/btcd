package elliptic

import "math/big"

// Bitcoin's secp256k1 elliptic curve
// Reference: https://en.bitcoin.it/wiki/Secp256k1
var Secp256k1 = new(CurveParams)

func init() {
	var ok bool

	Secp256k1.P, ok = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	if !ok {
		panic("secp256k1: SetString: P")
	}
	Secp256k1.N, ok = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("secp256k1: SetString: N")
	}
	Secp256k1.A = new(big.Int).SetUint64(0)
	Secp256k1.B = new(big.Int).SetUint64(7)
	Secp256k1.Gx, ok = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	if !ok {
		panic("secp256k1: SetString: Gx")
	}
	Secp256k1.Gy, ok = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
	if !ok {
		panic("secp256k1: SetString: Gx")
	}
	Secp256k1.BitSize = 256
	Secp256k1.Name = "secp256k1"
}
