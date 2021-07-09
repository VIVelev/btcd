package encoding

// base58 encoding / decoding functions

import (
	"bytes"
	"math/big"
)

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var (
	alphabetInv map[byte]int
	fiftyEight  *big.Int
)

func init() {
	alphabetInv = make(map[byte]int, 58)
	for i, c := range alphabet {
		alphabetInv[byte(c)] = i
	}
	fiftyEight = big.NewInt(58)
}

// reverse takes a string as argument and return the reverse of string.
// TODO: Maybe deprecate this in favor of utils.Reverse?
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
	v, exp, p := new(big.Int), new(big.Int), new(big.Int)
	for max, i := len(s)-1, len(s)-1; i >= 0; i-- {
		v.SetUint64(uint64(alphabetInv[s[i]]))
		exp.Exp(fiftyEight, p.SetUint64(uint64(max-i)), nil)
		n.Add(n, v.Mul(v, exp))
	}
	return n.Bytes()
}
