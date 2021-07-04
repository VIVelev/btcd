package encoding

import (
	"strings"
	"testing"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/elliptic"
)

func TestAddress(t *testing.T) {
	priv := ecdsa.GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	address := Address(&priv.PublicKey, true, true)

	if strings.Compare(address, "n263UYMwVbYceYhUVsbo3vGxViSNvEP74z") != 0 {
		t.Errorf("FAIL")
	}
}
