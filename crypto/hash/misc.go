package hash

// Hash256 applies two rounds of sha256 as in bitcoin.
func Hash256(data []byte) [32]byte {
	buf := Sha256(data)
	return Sha256(buf[:])
}

// Hash160 applies sha256 followed by ripemd160
func Hash160(data []byte) [20]byte {
	buf := Sha256(data)
	return Ripemd160(buf[:])
}
