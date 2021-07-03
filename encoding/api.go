// Package encoding provides different encodings used in bitcoin
// and also utility functions that use this encodings.
package encoding

import (
	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/hash"
)

// Address returns the associated bitcoin address for the public key as string.
func Address(pub *ecdsa.PublicKey, compressed, testnet bool) string {
	var netPkbHashCheck [25]byte // this is the raw (non-encoded) bitcoin address
	if compressed {
		src := hash.Hash160(pub.MarshalCompressed())
		copy(netPkbHashCheck[1:21], src[:])
	} else {
		src := hash.Hash160(pub.Marshal())
		copy(netPkbHashCheck[1:21], src[:])
	}
	if testnet {
		netPkbHashCheck[0] = 0x6f
	} else {
		netPkbHashCheck[0] = 0x00
	}

	// calculate the checksum
	checksum := hash.Hash256(netPkbHashCheck[:21])
	copy(netPkbHashCheck[21:], checksum[:4])

	// encode in base58 and return
	return base58encode(netPkbHashCheck[:])
}
