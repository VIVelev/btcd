package hash

// Hash256 applies two rounds of sha256 as in bitcoin.
func Hash256(data []byte) [32]byte {
	buf := Sha256(data)
	return Sha256(buf[:])
}
