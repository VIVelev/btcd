// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
package ecdsa

import (
	"math/big"
	"math/rand"

	"github.com/VIVelev/btcd/crypto/elliptic"
	"github.com/VIVelev/btcd/crypto/sha256"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// Sign computes the signature pair r and s from D and msgDigest.
func (priv *PrivateKey) Sign(msgDigest []byte) *Signature {
	// Obtain the group order n of the curve.
	n := priv.Curve.Params().N

	// Generate a cryptographically secure random number k between 1 and n-1.
	// It should be deterministic.
	rand.Seed(new(big.Int).SetBytes(msgDigest).Int64())
	kBytes := make([]byte, priv.Curve.Params().BitSize/8)
RESTART:
	rand.Read(kBytes)
	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, n)
	if k.Sign() == 0 {
		goto RESTART
	}

	// Compute (x, y) = k*G, where G is the generator point.
	x, _ := priv.Curve.ScalarBaseMult(k)

	// Calculate the signature.
	sig := new(Signature)
	// Compute r = x mod n. If r=0, generate another random k and start over.
	sig.r = new(big.Int).Mod(x, n)
	if sig.r.Sign() == 0 {
		goto RESTART
	}
	// Compute s = (msgDigest + r*D) / k mod n. If s=0, generate another random k and start over.
	sig.s = new(big.Int).SetBytes(msgDigest)
	prod := new(big.Int).Mul(sig.r, priv.D)
	sig.s.Add(sig.s, prod)
	kInv := new(big.Int).ModInverse(k, n)
	sig.s.Mul(sig.s, kInv)
	sig.s.Mod(sig.s, n)
	if sig.s.Sign() == 0 {
		goto RESTART
	}

	return sig
}

// Signature represents an ECDSA signature.
type Signature struct {
	r *big.Int
	s *big.Int
}

// Verify reports whether the signature pair r and s, pub and msgDigest are all consistent.
func (sig *Signature) Verify(pub *PublicKey, msgDigest []byte) bool {
	n := pub.Curve.Params().N

	// Verify that both r and s are between 1 and n-1.
	if sig.r.Sign() != 1 || new(big.Int).Sub(n, sig.r).Sign() != 1 {
		return false
	}
	if sig.s.Sign() != 1 || new(big.Int).Sub(n, sig.s).Sign() != 1 {
		return false
	}

	// Compute u1 = msgDigest/s mod n and u2 = r/s mod n.
	sInv := new(big.Int).ModInverse(sig.s, n)
	u1 := new(big.Int).SetBytes(msgDigest)
	u1.Mul(u1, sInv)
	u1.Mod(u1, n)
	u2 := new(big.Int).Set(sig.r)
	u2.Mul(u2, sInv)
	u2.Mod(u2, n)

	// Compute (x, y) = u1*G + u2*pub and ensure it is not equal to the point at infinity.
	u1X, u1Y := pub.Curve.ScalarBaseMult(u1)
	u2X, u2Y := pub.Curve.ScalarMult(pub.X, pub.Y, u2)
	x, y := pub.Curve.Add(u1X, u1Y, u2X, u2Y)
	// TODO: Isn't (x, y) = (0, 0) the point at infinity only for a subset of curves?
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}

	// If r = x mod n then the signature is valid. Otherwise, the signature is invalid.
	return x.Mod(x, n).Cmp(sig.r) == 0
}

// GenerateKey generates a public and private key pair from the passphrase.
func GenerateKey(c elliptic.Curve, passphrase string) *PrivateKey {
	priv := new(PrivateKey)
	priv.Curve = c
	buf := sha256.Hash256([]byte(passphrase))
	priv.D = new(big.Int).SetBytes(buf[:])
	priv.D.Mod(priv.D, priv.Curve.Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(priv.D)
	return priv
}
