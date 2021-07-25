package hash

// Reference: https://en.wikipedia.org/wiki/MurmurHash
// The following implementation is Murmur3_32bit for little-endian CPUs.

func murmurScramble(k uint32) uint32 {
	k *= 0xcc9e2d51
	k = (k << 15) | (k >> 17)
	k *= 0x1b873593
	return k
}

// Murmur3 returns a hash from the provided key using the specified seed.
func Murmur3(key []byte, seed uint32) (hash uint32) {
	hash = seed
	var k uint32
	nbytes := uint32(len(key))

	// Read in groups of 4.
	for i, n := uint32(0), nbytes/4*4; i < n; i += 4 {
		k = uint32(key[i]) | uint32(key[i+1])<<8 |
			uint32(key[i+2])<<16 | uint32(key[i+3])<<24

		hash ^= murmurScramble(k)
		hash = (hash << 13) | (hash >> 19)
		hash = hash*5 + 0xe6546b64
	}

	// Read the rest.
	k = 0
	for i := nbytes & 3; i > 0; i-- {
		k <<= 8
		k |= uint32(key[nbytes+i-4])
	}
	hash ^= murmurScramble(k)

	// Finalize.
	hash ^= nbytes
	hash ^= hash >> 16
	hash *= 0x85ebca6b
	hash ^= hash >> 13
	hash *= 0xc2b2ae35
	hash ^= hash >> 16
	return
}
