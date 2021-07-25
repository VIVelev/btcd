package network

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBloomFilterAdd(t *testing.T) {
	bf := BloomFilter{
		Size:         10,
		NumHashFuncs: 5,
		Tweak:        99,
	}
	bf.BitField = make([]byte, bf.Size*8)

	item := []byte("Hello World")
	bf.Add(item)
	want, _ := hex.DecodeString("0000000a080000000140")
	b, _ := bf.bytes()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}

	item = []byte("Goodbye!")
	bf.Add(item)
	want, _ = hex.DecodeString("4000600a080000010940")
	b, _ = bf.bytes()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}
