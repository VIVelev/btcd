package encoding

import (
	"bytes"
	"math"
	"math/big"
)

// base58 encoding / decoding functions
// reference: https://en.bitcoin.it/wiki/Base58Check_encoding

const (
	alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)

// reverse takes a string as
// argument and return the reverse of string.
func reverse(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		// swap the letters of the string,
		// like first with last and so on.
		rns[i], rns[j] = rns[j], rns[i]
	}
	// return the reversed string.
	return string(rns)
}

func base58encode(buf []byte) string {
	var chars []byte
	fiftyEight := big.NewInt(58)

	for n, m := new(big.Int).SetBytes(buf), big.NewInt(0); n.Sign() > 0; {
		n.DivMod(n, fiftyEight, m)
		chars = append(chars, alphabet[m.Uint64()])
	}

	// handle the leading 0 bytes
	numLeadingZeros := len(buf) - len(bytes.TrimLeft(buf, "\x00"))
	for i := 0; i < numLeadingZeros; i++ {
		chars = append(chars, alphabet[0])
	}

	return reverse(string(chars))
}

func base58decode(s string) []byte {
	n := big.NewInt(0)
	for max, i := len(s)-1, len(s)-1; i >= 0; i-- {
		n.Add(n, big.NewInt(int64(alphabet[i])*int64(math.Pow(58, float64(max-i)))))
	}
	return n.Bytes()
}
