package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	mysha256 "github.com/VIVelev/btcd/crypto/sha256"
)

func main() {
	msg := []byte("Hello World")

	sum := sha256.Sum256(msg)
	mySum := mysha256.Sha256(msg)

	fmt.Printf("%v\n%v\n", hex.EncodeToString(sum[:]), hex.EncodeToString(mySum[:]))
}
