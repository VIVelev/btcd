package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/VIVelev/btcd/crypto"
)

func main() {
	msg := []byte("Hello World")

	sum := sha256.Sum256(msg)
	mySum := crypto.Sha256(msg)

	fmt.Printf("%v\n%v\n", hex.EncodeToString(sum[:]), hex.EncodeToString(mySum[:]))
}
