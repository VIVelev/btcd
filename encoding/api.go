// Package encoding provides different encodings used in bitcoin
// and also utility functions that use this encodings.
package encoding

import (
	"bytes"
	"errors"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/hash"
)

// Address returns the associated bitcoin address in base58check for
// the public key as string.
//
// reference: https://en.bitcoin.it/wiki/Base58Check_encoding
func Address(pub *ecdsa.PublicKey, compressed, testnet bool) string {
	// this is the raw (non-encoded) bitcoin address
	var netPkHashCheck [25]byte
	if compressed {
		src := hash.Hash160(pub.MarshalCompressed())
		copy(netPkHashCheck[1:21], src[:])
	} else {
		src := hash.Hash160(pub.Marshal())
		copy(netPkHashCheck[1:21], src[:])
	}
	if testnet {
		netPkHashCheck[0] = 0x6f
	} else {
		netPkHashCheck[0] = 0x00
	}

	// calculate the checksum
	checksum := hash.Hash256(netPkHashCheck[:21])
	copy(netPkHashCheck[21:], checksum[:4])

	// encode in base58 and return
	return base58encode(netPkHashCheck[:])
}

// AddressToPubKeyHash recovers the public key hash from an address
// in base58check.
//
// Returns error if the checksum doesn't match.
func AddressToPubKeyHash(address string) ([]byte, error) {
	netPkHashCheck := base58decode(address)
	// validate the checksum
	b := len(netPkHashCheck) - 4
	checksum := hash.Hash256(netPkHashCheck[:b])
	if !bytes.Equal(netPkHashCheck[b:], checksum[:4]) {
		return nil, errors.New("AddressToPubKeyHash: checksum doesn't match")
	}
	// return the hash, stripping the version byte and checksum bytes
	return netPkHashCheck[1:b], nil
}
