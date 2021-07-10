package network

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

var (
	msg1Bytes []byte
	msg2Bytes []byte
)

func TestMain(m *testing.M) {
	msg1Bytes, _ = hex.DecodeString("f9beb4d976657261636b000000000000000000005df6e0e2")
	msg2Bytes, _ = hex.DecodeString("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")

	os.Exit(m.Run())
}

func TestMessageMarshal(t *testing.T) {
	msg, _ := new(Message).Unmarshal(bytes.NewReader(msg1Bytes))
	if !bytes.Equal(msg.Marshal(), msg1Bytes) {
		t.Errorf("FAIL")
	}

	msg.Unmarshal(bytes.NewReader(msg2Bytes))
	if !bytes.Equal(msg.Marshal(), msg2Bytes) {
		t.Errorf("FAIL")
	}
}

func TestMessageUnmarshal(t *testing.T) {
	msg, _ := new(Message).Unmarshal(bytes.NewReader(msg1Bytes))
	if strings.Compare(msg.Command, "verack") != 0 {
		t.Errorf("FAIL")
	}
	if len(msg.Payload) != 0 {
		t.Errorf("FAIL")
	}

	msg.Unmarshal(bytes.NewReader(msg2Bytes))
	if strings.Compare(msg.Command, "version") != 0 {
		t.Errorf("FAIL")
	}
	if !bytes.Equal(msg.Payload, msg2Bytes[24:]) {
		t.Errorf("FAIL")
	}
}

func TestVersionMsgMarshal(t *testing.T) {
	vm := VersionMsg{
		Version:   70015,
		Services:  0,
		Timestamp: 0,
		AddrRecv: NetAddr{
			Services: 0,
			IPv6v4:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
			Port:     8333,
		},
		AddrSndr: NetAddr{
			Services: 0,
			IPv6v4:   [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
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
