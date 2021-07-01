package ecdsa

import (
	"math/big"
	"testing"

	"github.com/VIVelev/btcd/crypto/elliptic"
)

func TestGenerateKey(t *testing.T) {
	priv := GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")

	target, _ := new(big.Int).SetString("9522859812228304878439346382140496201827824040581168239969151541141429165742", 10)
	if priv.K.Cmp(target) != 0 {
		t.Errorf("FAIL")
	}
}
