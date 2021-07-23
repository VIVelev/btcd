package network

import (
	"bytes"
	"encoding/hex"
	"net"
	"strings"
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
	b, _ := vm.marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestGetHeadersMsgMarshal(t *testing.T) {
	gh := GetHeadersMsg{
		Version:    70015,
		NumHashes:  1,
		StartBlock: "0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3",
		EndBlock:   "0000000000000000000000000000000000000000000000000000000000000000",
	}
	b, _ := gh.marshal()
	want, _ := hex.DecodeString("7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestHeadersMsgUnmarshal(t *testing.T) {
	hm := new(HeadersMsg)
	hm.unmarshal(hex.NewDecoder(strings.NewReader("0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600j")))
	if len(hm.Headers) != 2 {
		t.Errorf("FAIL")
	}
}
