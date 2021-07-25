package network

import (
	"errors"

	"github.com/VIVelev/btcd/crypto/hash"
)

const bip0037seed = uint32(0xfba4c795)

// Bloom filter as used in the Bitcoin protocol.
// https://en.wikipedia.org/wiki/Bloom_filter
type BloomFilter struct {
	Size         uint32 // Size of the bit field in bytes.
	BitField     []byte // The buckets (sets).
	NumHashFuncs uint32 // The number of hash functions.
	Tweak        uint32 // To be able to change the Bloom filter if it hits too many items.
}

// Add an item (bytes) to the filter.
// It basically encodes it into the BitField.
func (b *BloomFilter) Add(item []byte) {
	bitfieldSize := b.Size * 8
	for i := uint32(0); i < b.NumHashFuncs; i++ {
		seed := i*bip0037seed + b.Tweak
		h := hash.Murmur3(item, seed)
		b.BitField[h%bitfieldSize] = 1
	}
}

// bytes returns a compact (squished) byte representation of the BitField.
func (b *BloomFilter) bytes() ([]byte, error) {
	if len(b.BitField)%8 != 0 {
		return nil, errors.New("BitField must have length divisible by 8")
	}

	ret := make([]byte, len(b.BitField)/8)
	for i, bit := range b.BitField {
		byteIdx, bitIdx := i/8, i%8
		if bit == 1 {
			ret[byteIdx] |= 1 << bitIdx
		}
	}
	return ret, nil
}
