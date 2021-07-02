package hash

import "github.com/VIVelev/btcd/crypto/hash/xripemd160"

// Implementing SHA-256 from scratch was fun, however, for RIPEMD160
// I am taking an existing implementation.

func Ripemd160(data []byte) [20]byte {
	h := xripemd160.New()
	h.Write(data)
	var ret [20]byte
	copy(ret[:], h.Sum(nil))
	return ret
}
