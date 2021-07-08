// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in https://en.bitcoin.it/wiki/Elliptic_Curve_Digital_Signature_Algorithm
package ecdsa

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"math/big"

	"github.com/VIVelev/btcd/crypto/elliptic"
	"github.com/VIVelev/btcd/crypto/hash"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func (pub *PublicKey) Marshal() []byte {
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func (pub *PublicKey) MarshalCompressed() []byte {
	return elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
}

func (pub *PublicKey) Unmarshal(buf []byte) *PublicKey {
	pub.X, pub.Y = elliptic.Unmarshal(pub.Curve, buf)
	return pub
}

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

func (priv *PrivateKey) deterministicRandomInt(z []byte) *big.Int {
	length := len(z)
	k, v := make([]byte, length), make([]byte, length)
	for i := 0; i < len(z); i++ {
		k[i] = 0x00
		v[i] = 0x01
	}
	zInt := new(big.Int).SetBytes(z)
	if zInt.Cmp(priv.Curve.Params().N) == 1 {
		zInt.Sub(zInt, priv.Curve.Params().N)
	}
	z = zInt.Bytes()
	secretBytes := make([]byte, length)
	copy(secretBytes[length-(priv.D.BitLen()+7)/8:], priv.D.Bytes())

	b := append(v, 0x00)
	b = append(b, secretBytes...)
	b = append(b, z...)
	h := hmac.New(sha256.New, k)
	h.Write(b)
	k = h.Sum(nil)
	h = hmac.New(sha256.New, k)
	h.Write(v)
	v = h.Sum(nil)
	b = append(v, 0x01)
	b = append(b, secretBytes...)
	b = append(b, z...)
	h = hmac.New(sha256.New, k)
	h.Write(b)
	k = h.Sum(nil)
	h = hmac.New(sha256.New, k)
	h.Write(v)
	v = h.Sum(nil)

	for {
		h = hmac.New(sha256.New, k)
		h.Write(v)
		v = h.Sum(nil)
		candidate := new(big.Int).SetBytes(v)
		if candidate.Sign() == 1 && candidate.Cmp(priv.Curve.Params().N) == -1 {
			return candidate
		}
		h = hmac.New(sha256.New, k)
		h.Write(append(v, 0x00))
		k = h.Sum(nil)
		h = hmac.New(sha256.New, k)
		h.Write(v)
		v = h.Sum(nil)
	}
}

// Sign computes the signature pair r and s from D and msgDigest.
func (priv *PrivateKey) Sign(msgDigest []byte) *Signature {
	// Obtain the group order n of the curve.
	n := priv.Curve.Params().N

RESTART:
	k := priv.deterministicRandomInt(msgDigest)
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

	// It turns out that using the low-s value will get nodes to relay our transactions.
	// This is for malleability reasons.
	halfN := new(big.Int).Div(n, big.NewInt(2))
	if sig.s.Cmp(halfN) == 1 {
		sig.s.Sub(n, sig.s)
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

// Marshal encodes sig in DER format.
//
// DER has the following format:
// 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
//
// total-length: 1-byte length descriptor of everything that follows.
// r-length: 1-byte length descriptor of the r value that follows.
// r: arbitrary-length big-endian encoded r value. It cannot start with any 0x00 bytes,
// unless the first byte that follows is 0x80 or higher, in which case a single 0x00 is required.
// s-length: 1-byte length descriptor of the s value that follows.
// s: arbitrary-length big-endian encoded s value. The same rules apply as for r.
func (sig *Signature) Marshal() []byte {
	encode := func(n *big.Int) []byte {
		nb := n.Bytes()
		nb = bytes.TrimLeft(nb, "\x00")
		if nb[0] >= 0x80 {
			nb = append([]byte{0}, nb...)
		}
		return nb
	}

	rb := encode(sig.r)
	rbLen := byte(len(rb))
	sb := encode(sig.s)
	sbLen := byte(len(sb))
	u := []byte{0x30, 2 + rbLen + 2 + sbLen, 0x02, rbLen}
	v := []byte{0x02, sbLen}
	return bytes.Join([][]byte{u, rb, v, sb}, nil)
}

// Unmarshal decodes DER format to sig.
func (sig *Signature) Unmarshal(der []byte) *Signature {
	s := bytes.NewReader(der)

	// read and validate 0x30 prefix
	b, err := s.ReadByte()
	if err != nil {
		panic(err)
	}
	if b != 0x30 {
		panic("der signatures should begin with 0x30 byte")
	}

	// read and validate total-length
	totalLength, err := s.ReadByte()
	if err != nil {
		panic(err)
	}
	if totalLength != byte(len(der)-2) {
		panic("total-length does not match")
	}

	// read and validate marker
	b, err = s.ReadByte()
	if err != nil {
		panic(err)
	}
	if b != 0x02 {
		panic("invalid marker")
	}

	// read r
	rbLen, err := s.ReadByte()
	if err != nil {
		panic(err)
	}
	rb := make([]byte, rbLen)
	n, err := s.Read(rb)
	if err != nil {
		panic(err)
	}
	if n != int(rbLen) {
		panic("couldn't read the whole r")
	}

	// read and validate marker
	b, err = s.ReadByte()
	if err != nil {
		panic(err)
	}
	if b != 0x02 {
		panic("invalid marker")
	}

	// read s
	sbLen, err := s.ReadByte()
	if err != nil {
		panic(err)
	}
	sb := make([]byte, sbLen)
	n, err = s.Read(sb)
	if err != nil {
		panic(err)
	}
	if n != int(sbLen) {
		panic("couldn't read the whole s")
	}

	// validate lengths
	if 6+rbLen+sbLen != byte(len(der)) { // 6 is the number of misc bytes
		panic("read length doesn't match der length")
	}

	sig.r = new(big.Int).SetBytes(rb)
	sig.s = new(big.Int).SetBytes(sb)
	return sig
}

// GenerateKey generates a public and private key pair from the passphrase.
func GenerateKey(c elliptic.Curve, passphrase string) *PrivateKey {
	priv := new(PrivateKey)
	priv.Curve = c
	buf := hash.Hash256([]byte(passphrase))
	priv.D = new(big.Int).SetBytes(buf[:])
	priv.D.Mod(priv.D, priv.Curve.Params().N)
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(priv.D)
	return priv
}
