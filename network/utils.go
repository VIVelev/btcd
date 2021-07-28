package network

func bytesToBitField(b []byte) (bitField []byte) {
	bitField = make([]byte, len(b)*8)
	for i, x := range b {
		for j := 0; j < 8; j++ {
			bitField[i*8+j] = x & 1
			x >>= 1
		}
	}
	return
}
