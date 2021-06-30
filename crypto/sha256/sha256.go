/*
follows the FIPS PUB 180-4 description for calculating SHA-256 hash function
https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

noone in their right mind should use this for any serious reason;
this was written purely for educational purposes
*/
package sha256

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
)

type word [4]byte // 32 bits

func (w word) Uint32() uint32 {
	return binary.BigEndian.Uint32(w[:])
}

func (w word) String() string {
	return fmt.Sprintf("%v", hex.EncodeToString(w[:]))
}

// -----------------------------------------------------------------------------
// SHA-256 Functions, defined in Sections 3.2 and 4.1.2

// rotate right (circular right shift)
func rotr(n int, x word) (res word) {
	xInt := x.Uint32()
	binary.BigEndian.PutUint32(res[:], (xInt>>n)|(xInt<<(32-n)))
	return
}

// right shift
func shr(n int, x word) (res word) {
	xInt := x.Uint32()
	binary.BigEndian.PutUint32(res[:], xInt>>n)
	return
}

func ch(x, y, z word) (res word) {
	xInt := x.Uint32()
	yInt := y.Uint32()
	zInt := z.Uint32()
	binary.BigEndian.PutUint32(res[:], (xInt&yInt)^((^xInt)&zInt))
	return
}

func maj(x, y, z word) (res word) {
	xInt := x.Uint32()
	yInt := y.Uint32()
	zInt := z.Uint32()
	binary.BigEndian.PutUint32(res[:], (xInt&yInt)^(xInt&zInt)^(yInt&zInt))
	return
}

func capsig0(x word) (res word) {
	binary.BigEndian.PutUint32(res[:], rotr(2, x).Uint32()^rotr(13, x).Uint32()^rotr(22, x).Uint32())
	return
}

func capsig1(x word) (res word) {
	binary.BigEndian.PutUint32(res[:], rotr(6, x).Uint32()^rotr(11, x).Uint32()^rotr(25, x).Uint32())
	return
}

func sig0(x word) (res word) {
	binary.BigEndian.PutUint32(res[:], rotr(7, x).Uint32()^rotr(18, x).Uint32()^shr(3, x).Uint32())
	return
}

func sig1(x word) (res word) {
	binary.BigEndian.PutUint32(res[:], rotr(17, x).Uint32()^rotr(19, x).Uint32()^shr(10, x).Uint32())
	return
}

// -----------------------------------------------------------------------------
// SHA-256 Constants

/*
follows Section 4.2.2 to generate K

the first 32 bits of the fractional parts of the cube roots of the first
64 prime numbers:

428a2f98 71374491 b5c0fbcf e9b5dba5 3956c25b 59f111f1 923f82a4 ab1c5ed5
d807aa98 12835b01 243185be 550c7dc3 72be5d74 80deb1fe 9bdc06a7 c19bf174
e49b69c1 efbe4786 0fc19dc6 240ca1cc 2de92c6f 4a7484aa 5cb0a9dc 76f988da
983e5152 a831c66d b00327c8 bf597fc7 c6e00bf3 d5a79147 06ca6351 14292967
27b70a85 2e1b2138 4d2c6dfc 53380d13 650a7354 766a0abb 81c2c92e 92722c85
a2bfe8a1 a81a664b c24b8b70 c76c51a3 d192e819 d6990624 f40e3585 106aa070
19a4c116 1e376c08 2748774c 34b0bcb5 391c0cb3 4ed8aa4a 5b9cca4f 682e6ff3
748f82ee 78a5636f 84c87814 8cc70208 90befffa a4506ceb bef9a3f7 c67178f2
*/
func genK() (K [64]word) {
	for i, p := range firstNPrimes(64) {
		binary.BigEndian.PutUint32(K[i][:], uint32(fracBin(math.Pow(float64(p), 1/3.), 32)))
	}
	return
}

/*
follows Section 5.3.3 to generate the initial hash value H^0

the first 32 bits of the fractional parts of the square roots of the first
8 prime numbers:

6a09e667 bb67ae85 3c6ef372 a54ff53a 9b05688c 510e527f 1f83d9ab 5be0cd19
*/
func genH() (H [8]word) {
	for i, p := range firstNPrimes(8) {
		binary.BigEndian.PutUint32(H[i][:], uint32(fracBin(math.Sqrt(float64(p)), 32)))
	}
	return
}

// -----------------------------------------------------------------------------

// follows Section 5.1.1 to pad the message
// the result's length is multiple of 512 bits (64 bytes)
func pad(data []byte) []byte {
	// len of data in bits
	l := uint64(len(data) * 8)

	// append just "1" to the end of data
	data = append(data, 0b10000000)

	// follow by k zero bits, where k is the smallest, non-negative solution to
	// l + 1 + k = 448 mod 512
	// i.e. pad with zeros until we reach 448 (mod 512)
	for (len(data)*8)%512 != 448 {
		data = append(data, 0x00)
	}

	// the last 64-bit block is the length l of the original data
	// expressed in binary (big endian)
	lbytes := [8]byte{}
	binary.BigEndian.PutUint64(lbytes[:], l)
	data = append(data, lbytes[:]...)

	return data
}

func Sha256(data []byte) [32]byte {
	// Section 4.2: Constants
	K := genK()

	// Section 5: Preprocessing
	// Section 5.1: Pad the message

	data = pad(data)
	// Section 5.2: Separate the message into blocks of 512 bits (64 bytes)
	blocks := make([][64]byte, len(data)/64)
	for i := range blocks {
		copy(blocks[i][:], data[i*64:(i+1)*64])
	}
	// Section 5.3: Setting the Iniial Hash Value
	H := genH()

	// Section 6
	for _, M := range blocks {

		// 1. Prepare the message schedule, a 64-entry array of 32-bit words
		W := [64]word{}
		for t := range W {
			if t <= 15 {
				// the first 16 words are just a copy of the block
				copy(W[t][:], M[t*4:(t+1)*4])
			} else {
				term1 := sig1(W[t-2]).Uint32()
				term2 := W[t-7].Uint32()
				term3 := sig0(W[t-15]).Uint32()
				term4 := W[t-16].Uint32()
				total := term1 + term2 + term3 + term4
				binary.BigEndian.PutUint32(W[t][:], total)
			}
		}

		// 2. Initialize the 8 working variables a,b,c,d,e,f,g,h with prev hash value
		a, b, c, d, e, f, g, h := H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]

		// 3.
		for t := range W {
			T1 := h.Uint32() + capsig1(e).Uint32() + ch(e, f, g).Uint32() + K[t].Uint32() + W[t].Uint32()
			T2 := capsig0(a).Uint32() + maj(a, b, c).Uint32()
			h = g
			g = f
			f = e
			binary.BigEndian.PutUint32(e[:], d.Uint32()+T1)
			d = c
			c = b
			b = a
			binary.BigEndian.PutUint32(a[:], T1+T2)
		}

		// 4. Compute the i-th intermediate hash value H^i
		delta := [8]word{a, b, c, d, e, f, g, h}
		for i := range H {
			binary.BigEndian.PutUint32(H[i][:], H[i].Uint32()+delta[i].Uint32())
		}
	}

	res := [32]byte{}
	copy(res[0:], H[0][:])
	copy(res[4:], H[1][:])
	copy(res[8:], H[2][:])
	copy(res[12:], H[3][:])
	copy(res[16:], H[4][:])
	copy(res[20:], H[5][:])
	copy(res[24:], H[6][:])
	copy(res[28:], H[7][:])
	return res
}
