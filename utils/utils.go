package utils

func Reversed(s []byte) (r []byte) {
	r = make([]byte, len(s))
	copy(r, s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return
}
