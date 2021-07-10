package blockchain

import (
	"encoding/binary"
	"io"

	"github.com/VIVelev/btcd/utils"
)

// Block represents a Bitcoin block header.
type Block struct {
	Version        uint32
	HashPrevBlock  [32]byte
	HashMerkleRoot [32]byte
	Timestamp      uint32
	Bits           [4]byte
	Nonce          [4]byte
}

func (b *Block) Marshal() [80]byte {
	var ret [80]byte
	// Version, 4 bytes, little-endian
	binary.LittleEndian.PutUint32(ret[:4], b.Version)
	// HashPrevBlock, 32 bytes, little-endian
	copy(ret[4:36], utils.Reverse(b.HashPrevBlock[:]))
	// HashMerkleRoot, 32 bytes, little-endian
	copy(ret[36:68], utils.Reverse(b.HashMerkleRoot[:]))
	// Timestamp, 4 bytes, little-endian
	binary.LittleEndian.PutUint32(ret[68:72], b.Timestamp)
	// Bits, 4 bytes
	copy(ret[72:76], b.Bits[:])
	// Nonce, 4 byte
	copy(ret[76:], b.Nonce[:])

	return ret
}

func (b *Block) Unmarshal(r io.Reader) *Block {
	// Version, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &b.Version)
	// HashPrevBlock, 32 bytes, little-endian
	var le [32]byte
	io.ReadFull(r, le[:])
	copy(b.HashPrevBlock[:], utils.Reverse(le[:]))
	// HashMerkleRoot, 32 bytes, little-endian
	io.ReadFull(r, le[:])
	copy(b.HashMerkleRoot[:], utils.Reverse(le[:]))
	// Timestamp, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &b.Timestamp)
	// Bits, 4 bytes
	io.ReadFull(r, b.Bits[:])
	// None, 4 bytes
	io.ReadFull(r, b.Nonce[:])

	return b
}
