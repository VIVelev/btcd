package network

import (
	"bytes"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"testing"
)

var (
	envlp1Bytes []byte
	envlp2Bytes []byte
)

func TestMain(m *testing.M) {
	envlp1Bytes, _ = hex.DecodeString("f9beb4d976657261636b000000000000000000005df6e0e2")
	envlp2Bytes, _ = hex.DecodeString("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")

	os.Exit(m.Run())
}

func TestEnvelopeMarshal(t *testing.T) {
	e, _ := new(Envelope).Unmarshal(bytes.NewReader(envlp1Bytes))
	if !bytes.Equal(e.Marshal(), envlp1Bytes) {
		t.Errorf("FAIL")
	}

	e.Unmarshal(bytes.NewReader(envlp2Bytes))
	if !bytes.Equal(e.Marshal(), envlp2Bytes) {
		t.Errorf("FAIL")
	}
}

func TestEnvelopeUnmarshal(t *testing.T) {
	e, _ := new(Envelope).Unmarshal(bytes.NewReader(envlp1Bytes))
	if strings.Compare(e.Command, "verack") != 0 {
		t.Errorf("FAIL")
	}
	if len(e.Payload) != 0 {
		t.Errorf("FAIL")
	}

	e.Unmarshal(bytes.NewReader(envlp2Bytes))
	if strings.Compare(e.Command, "version") != 0 {
		t.Errorf("FAIL")
	}
	if !bytes.Equal(e.Payload, envlp2Bytes[24:]) {
		t.Errorf("FAIL")
	}
}

func TestHandshake(t *testing.T) {
	conn, err := net.Dial("tcp", "testnet.programmingbitcoin.com:18333")
	if err != nil {
		t.Error(err)
	}
	node := &Node{
		Conn:    conn,
		Testnet: true,
		Logging: false,
	}
	err = node.Handshake()
	if err != nil {
		t.Error(err)
	}
}
