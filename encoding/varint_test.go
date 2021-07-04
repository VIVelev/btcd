package encoding

import (
	"bytes"
	"math/big"
	"testing"
)

var (
	a, _ = new(big.Int).SetString("fc", 16)
	b, _ = new(big.Int).SetString("ffff", 16)
	c, _ = new(big.Int).SetString("ffffffff", 16)
	d, _ = new(big.Int).SetString("ffffffffffffffff", 16)
)

func TestVarIntSize(t *testing.T) {
	var (
		aEnc, _ = EncodeVarInt(a)
		bEnc, _ = EncodeVarInt(b)
		cEnc, _ = EncodeVarInt(c)
		dEnc, _ = EncodeVarInt(d)
	)

	if len(aEnc) != 1 {
		t.Errorf("FAIL")
	}
	if len(bEnc) != 3 {
		t.Errorf("FAIL")
	}
	if len(cEnc) != 5 {
		t.Errorf("FAIL")
	}
	if len(dEnc) != 9 {
		t.Errorf("FAIL")
	}
}

func TestEncodeDecodeVarInt(t *testing.T) {
	var (
		aEnc, _ = EncodeVarInt(a)
		bEnc, _ = EncodeVarInt(b)
		cEnc, _ = EncodeVarInt(c)
		dEnc, _ = EncodeVarInt(d)
	)
	var (
		aDec = DecodeVarInt(bytes.NewReader(aEnc))
		bDec = DecodeVarInt(bytes.NewReader(bEnc))
		cDec = DecodeVarInt(bytes.NewReader(cEnc))
		dDec = DecodeVarInt(bytes.NewReader(dEnc))
	)

	if aDec.Cmp(a) != 0 {
		t.Errorf("FAIL")
	}
	if bDec.Cmp(b) != 0 {
		t.Errorf("FAIL")
	}
	if cDec.Cmp(c) != 0 {
		t.Errorf("FAIL")
	}
	if dDec.Cmp(d) != 0 {
		t.Errorf("FAIL")
	}
}
