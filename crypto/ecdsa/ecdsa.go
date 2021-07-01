// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
package ecdsa

import (
	"math/big"

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
	K *big.Int
}

// Signature represents an ECDSA signature.
type Signature struct {
	r *big.Int
	s *big.Int
}

// GenerateKey generates a public and private key pair from the passphrase.
func GenerateKey(c elliptic.Curve, passphrase string) *PrivateKey {
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	// as K is at max 256 bits, it is less than the Curve's N
	buf := sha256.Hash256([]byte(passphrase))
	priv.K = new(big.Int).SetBytes(buf[:])
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(priv.K)
	return priv
}
