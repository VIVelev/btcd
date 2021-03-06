package ecdsa

import (
	"math/big"
	"testing"

	"github.com/VIVelev/btcd/crypto/elliptic"
	"github.com/VIVelev/btcd/crypto/hash"
)

func TestGenerateKey(t *testing.T) {
	priv := GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	target, _ := new(big.Int).SetString("9522859812228304878439346382140496201827824040581168239969151541141429165742", 10)
	if priv.D.Cmp(target) != 0 {
		t.Errorf("FAIL")
	}
}

func TestSignVerify(t *testing.T) {
	priv := GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	msgDigest := hash.Hash256([]byte("Ford Prefect is also from Betelgeuse!"))
	sig := priv.Sign(msgDigest[:])
	if !sig.Verify(&priv.PublicKey, msgDigest[:]) {
		t.Errorf("FAIL")
	}
}

func TestSignVerifyFail(t *testing.T) {
	priv := GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	msgDigest := hash.Hash256([]byte("Ford Prefect is also from Betelgeuse!"))
	sig := priv.Sign(msgDigest[:])

	wrongPriv := GenerateKey(elliptic.Secp256k1, "notfrombetelgeuse")
	if sig.Verify(&wrongPriv.PublicKey, msgDigest[:]) {
		t.Errorf("FAIL")
	}
}

func TestSignatureMarshalling(t *testing.T) {
	priv := GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	msgDigest := hash.Hash256([]byte("Ford Prefect is also from Betelgeuse!"))
	sig := priv.Sign(msgDigest[:])

	der := sig.Marshal()
	sig2, _ := new(Signature).Unmarshal(der)
	if sig2.r.Cmp(sig.r) != 0 || sig2.s.Cmp(sig.s) != 0 {
		t.Errorf("FAIL")
	}

}
