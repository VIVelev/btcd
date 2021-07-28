package blockchain

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"
)

var blockBytes []byte

func TestMain(m *testing.M) {
	blockBytes, _ = hex.DecodeString("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")

	os.Exit(m.Run())
}

func TestMarshal(t *testing.T) {
	block := new(Block).Unmarshal(bytes.NewReader(blockBytes))
	b := block.Marshal()
	if !bytes.Equal(b[:], blockBytes) {
		t.Errorf("FAIL")
	}
}

func TestUnmarshal(t *testing.T) {
	block := new(Block).Unmarshal(bytes.NewReader(blockBytes))

	if block.Version != 0x20000002 {
		t.Errorf("FAIL")
	}

	want, _ := hex.DecodeString("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e")
	if !bytes.Equal(block.PrevBlock[:], want) {
		t.Errorf("FAIL")
	}
	want, _ = hex.DecodeString("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b")
	if !bytes.Equal(block.MerkleRoot[:], want) {
		t.Errorf("FAIL")
	}

	if block.Timestamp != 0x59a7771e {
		t.Errorf("FAIL")
	}

	want, _ = hex.DecodeString("e93c0118")
	if !bytes.Equal(block.Bits[:], want) {
		t.Errorf("FAIL")
	}
	want, _ = hex.DecodeString("a4ffd71d")
	if !bytes.Equal(block.Nonce[:], want) {
		t.Errorf("FAIL")
	}
}

func TestTarget(t *testing.T) {
	block := new(Block).Unmarshal(bytes.NewReader(blockBytes))

	want, _ := new(big.Int).SetString("13ce9000000000000000000000000000000000000000000", 16)
	if block.Target().Cmp(want) != 0 {
		t.Errorf("FAIL")
	}
}

func TestDifficulty(t *testing.T) {
	block := new(Block).Unmarshal(bytes.NewReader(blockBytes))

	want, _ := new(big.Int).SetString("888171856257", 10)
	if block.Difficulty().Cmp(want) != 0 {
		t.Errorf("FAIL")
	}
}

func TestVerifyPoW(t *testing.T) {
	block := new(Block).Unmarshal(bytes.NewReader(blockBytes))
	if !block.VerifyPoW() {
		t.Errorf("FAIL")
	}

	block.Unmarshal(hex.NewDecoder(strings.NewReader("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0")))
	if block.VerifyPoW() {
		t.Errorf("FAIL")
	}
}
