package blockchain

import (
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/crypto/hash"
	"github.com/VIVelev/btcd/utils"
)

var (
	MainGenesisBlockBytes, _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c")
	TestGenesisBlockBytes, _ = hex.DecodeString("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18")
)

// Block represents a Bitcoin block header, the metadata of a block.
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
	copy(ret[4:36], utils.Reversed(b.HashPrevBlock[:]))
	// HashMerkleRoot, 32 bytes, little-endian
	copy(ret[36:68], utils.Reversed(b.HashMerkleRoot[:]))
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
	copy(b.HashPrevBlock[:], utils.Reversed(le[:]))
	// HashMerkleRoot, 32 bytes, little-endian
	io.ReadFull(r, le[:])
	copy(b.HashMerkleRoot[:], utils.Reversed(le[:]))
	// Timestamp, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &b.Timestamp)
	// Bits, 4 bytes
	io.ReadFull(r, b.Bits[:])
	// None, 4 bytes
	io.ReadFull(r, b.Nonce[:])

	return b
}

func (b *Block) Id() string {
	m := b.Marshal()
	h256 := hash.Hash256(m[:])
	return hex.EncodeToString(utils.Reversed(h256[:]))
}

// Target returns the PoW target based on the bits.
func (b *Block) Target() *big.Int {
	exponent := b.Bits[3]
	var cb [4]byte
	copy(cb[:], b.Bits[:3])
	cb[3] = 0x00
	coefficient := binary.LittleEndian.Uint32(cb[:])
	// the formula is: coefficient * 256^(exponent - 3)
	ret := big.NewInt(int64(coefficient))
	power := new(big.Int).Exp(big.NewInt(256), big.NewInt(int64(exponent-3)), nil)
	return ret.Mul(ret, power)
}

// Difficulty returns the block (current mining) difficulty based on the bits.
// Difficulty is simply a human interpretable form of the target.
// The difficulty of the genesis block is 1. The formula is as follows:
//   difficulty = (target of lowest difficulty) / (current target)
func (b *Block) Difficulty() *big.Int {
	lowest := big.NewInt(0xffff)
	power := new(big.Int).Exp(big.NewInt(256), big.NewInt(0x1d-3), nil)
	lowest.Mul(lowest, power)
	return lowest.Div(lowest, b.Target())
}

// VerifyPoW returns whether this block satisfies the PoW.
func (b *Block) VerifyPoW() bool {
	m := b.Marshal()
	h256 := hash.Hash256(m[:])
	// interpret h256 as little-endian
	proof := new(big.Int).SetBytes(utils.Reversed(h256[:]))
	return proof.Cmp(b.Target()) == -1
}
