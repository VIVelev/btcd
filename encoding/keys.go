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

func DecodeAddress(s string) [20]byte {
	netPkHashCheck := base58decode(s)
	if len(netPkHashCheck) != 25 {
		panic("netPkHashCheck has length different than 25")
	}

	var check [4]byte
	copy(check[:], netPkHashCheck[21:])
	checksum := hash.Hash256(netPkHashCheck[:21])
	if !bytes.Equal(check[:], checksum[:4]) {
		panic("invalid address")
	}

	var pkHash160 [20]byte
	copy(pkHash160[:], netPkHashCheck[1:21])
	return pkHash160
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

// Wif encodes the private key in WIF format.
//
// WIF has the following format:
// [1 byte net id] [D in big-endian] [suffix if compressed] [4 bytes checksum]
//
// reference: https://en.bitcoin.it/wiki/Wallet_import_format
func Wif(priv *ecdsa.PrivateKey, compressed, testnet bool) string {
	privSize := (priv.Curve.Params().BitSize + 7) / 8
	size := 1 + privSize + 4
	if compressed {
		size += 1
	}
	wif := make([]byte, size)

	if testnet {
		wif[0] = 0xef
	} else {
		wif[0] = 0x80
	}
	priv.D.FillBytes(wif[1 : privSize+1])
	if compressed {
		wif[privSize+1] = 0x01
	}
	checksum := hash.Hash256(wif[:size-4])
	copy(wif[size-4:], checksum[:4])
	return base58encode(wif)
}
