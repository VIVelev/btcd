package network

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestVersionMsgMarshal(t *testing.T) {
	vm := VersionMsg{
		Version:   70015,
		Services:  0,
		Timestamp: 0,
		AddrRecv: NetAddr{
			Services: 0,
			IP:       net.ParseIP("0.0.0.0"),
			Port:     8333,
		},
		AddrSndr: NetAddr{
			Services: 0,
			IP:       net.ParseIP("0.0.0.0"),
			Port:     8333,
		},
		Nonce:     0,
		UserAgent: "/programmingbitcoin:0.1/",
		Height:    0,
		Relay:     false,
	}

	want, _ := hex.DecodeString("7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000")
	b, _ := vm.Marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}
