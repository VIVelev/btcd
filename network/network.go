// package network implements the Bitcoin peer-to-peer network protocol.
// reference: https://en.bitcoin.it/wiki/Protocol_documentation
package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/VIVelev/btcd/crypto/hash"
)

var (
	mainnetMagic = [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	testnetMagic = [4]byte{0x0b, 0x11, 0x09, 0x07}
)

type Envelope struct {
	Command string // up to 12 bytes
	Payload []byte
	Testnet bool
}

func (e *Envelope) Marshal() []byte {
	buf := new(bytes.Buffer)
	// network magic, 4 bytes
	if e.Testnet {
		buf.Write(testnetMagic[:])
	} else {
		buf.Write(mainnetMagic[:])
	}
	// Command, 12 bytes, human-readable
	buf.Write([]byte(e.Command))
	for i := len(e.Command); i < 12; i++ {
		buf.WriteByte(0x00)
	}
	// Payload length, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, uint32(len(e.Payload)))
	// Payload checksum, first 4 bytes of hash256(Payload)
	h256 := hash.Hash256(e.Payload)
	buf.Write(h256[:4])
	// Payload
	buf.Write(e.Payload)
	// return bytes
	return buf.Bytes()
}

func (e *Envelope) Unmarshal(r io.Reader) (*Envelope, error) {
	// check the network magic
	var magic [4]byte
	_, err := io.ReadFull(r, magic[:])
	if err != nil {
		return nil, errors.New("connection reset")
	}
	e.Testnet = bytes.Equal(magic[:], testnetMagic[:])
	// Command, 12 bytes, human-readable
	var cmdBytes [12]byte
	io.ReadFull(r, cmdBytes[:])
	e.Command = string(bytes.TrimRight(cmdBytes[:], "\x00"))
	// Payload length, 4 bytes, little-endian
	var payloadLength uint32
	binary.Read(r, binary.LittleEndian, &payloadLength)
	// Payload checksum, first 4 bytes of hash256(Payload)
	var checksum [4]byte
	io.ReadFull(r, checksum[:])
	// Payload
	e.Payload = make([]byte, payloadLength)
	io.ReadFull(r, e.Payload)

	// verify checksum
	h256 := hash.Hash256(e.Payload)
	if !bytes.Equal(h256[:4], checksum[:]) {
		return nil, errors.New("checksum doesn't match")
	}

	return e, nil
}

// Node is a utility struct used to connect to a single node.
type Node struct {
	Conn    net.Conn
	Testnet bool
	Logging bool
}

// Handshake performs Version Handshake
// ref: https://en.bitcoin.it/wiki/Version_Handshake
//
// Local peer (L) connects to a remote peer (R):
// L -> R: Send version message with the local peer's version
// L <- R: Send version message back
// L <- R: Send verack message
// R:      Sets version to the minimum of the 2 versions
// L -> R: Send verack message after receiving version message from R
// L:      Sets version to the minimum of the 2 versions
func (n *Node) Handshake() error {
	var err error

	// TODO: this version message is hardcoded
	err = n.Write(&VersionMsg{
		Version:   70015,
		Services:  0,
		Timestamp: time.Now().Unix(),
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
	})
	if err != nil {
		return err
	}

	if _, err = n.WaitFor("version"); err != nil {
		return err
	}
	if _, err = n.WaitFor("verack"); err != nil {
		return err
	}
	if err = n.Write(&VerackMsg{}); err != nil {
		return err
	}

	return nil
}

// Write writes the message to the connection.
func (n *Node) Write(m message) error {
	b, err := m.marshal()
	if err != nil {
		return err
	}
	e := Envelope{
		Command: m.command(),
		Payload: b,
		Testnet: n.Testnet,
	}

	if n.Logging {
		fmt.Printf("sending %s to %s\n", e.Command, n.Conn.RemoteAddr().String())
	}

	_, err = n.Conn.Write(e.Marshal())
	if err != nil {
		return err
	}
	return nil
}

// Read reads a message in a envelope from the connection.
func (n *Node) Read() (*Envelope, error) {
	var e *Envelope
	for {
		var err error
		e, err = new(Envelope).Unmarshal(n.Conn)
		if err == nil {
			break
		}
	}

	if n.Logging {
		fmt.Printf("receiving %s from %s\n", e.Command, n.Conn.RemoteAddr().String())
	}

	return e, nil
}

func (n *Node) WaitFor(cmds ...string) (message, error) {
	if n.Logging {
		fmt.Printf("Waiting for any of: %v\n", cmds)
	}

	contains := func(ss []string, s string) bool {
		for _, x := range ss {
			if strings.Compare(s, x) == 0 {
				return true
			}
		}
		return false
	}

	var command string
	var e *Envelope
	for !contains(cmds, command) {
		var err error
		e, err = n.Read()
		if err != nil {
			return nil, err
		}
		command = e.Command
		switch command {
		case "version":
		case "verack":
		case "sendheaders":
		case "sendcmpct":
		case "ping":
			msg := new(PingMsg)
			msg.unmarshal(bytes.NewReader(e.Payload))
			n.Write(&PongMsg{Nonce: msg.Nonce})
		case "feefilter":
		case "headers":
		case "inv":
		case "addr":
		default:
			return nil, fmt.Errorf("unknown command \"%s\"", command)
		}
	}

	switch command {
	case "version":
		return new(VersionMsg).unmarshal(bytes.NewReader(e.Payload)), nil
	case "verack":
		return nil, nil
	case "headers":
		return new(HeadersMsg).unmarshal(bytes.NewReader(e.Payload)), nil
	default:
		return nil, fmt.Errorf("unknown command \"%s\"", command)
	}
}

func (n *Node) Close() error {
	return n.Conn.Close()
}
