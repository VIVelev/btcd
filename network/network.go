// package network implements the Bitcoin peer-to-peer network protocol.
// reference: https://en.bitcoin.it/wiki/Protocol_documentation
package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/VIVelev/btcd/crypto/hash"
)

var (
	MainnetMagic = [4]byte{0xf9, 0xbe, 0xb4, 0xd9}
	TestnetMagic = [4]byte{0x0b, 0x11, 0x09, 0x07}
)

type Message struct {
	Command string // 12 bytes
	Payload []byte
	Testnet bool
}

func (m *Message) Marshal() []byte {
	buf := new(bytes.Buffer)
	// network magic, 4 bytes
	if m.Testnet {
		buf.Write(TestnetMagic[:])
	} else {
		buf.Write(MainnetMagic[:])
	}
	// Command, 12 bytes, human-readable
	buf.Write([]byte(m.Command))
	for i := len(m.Command); i < 12; i++ {
		buf.WriteByte(0x00)
	}
	// Payload length, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, uint32(len(m.Payload)))
	// Payload checksum, first 4 bytes of hash256(Payload)
	h256 := hash.Hash256(m.Payload)
	buf.Write(h256[:4])
	// Payload
	buf.Write(m.Payload)
	// return bytes
	return buf.Bytes()
}

func (m *Message) Unmarshal(r io.Reader) (*Message, error) {
	// check the network magic
	var magic [4]byte
	_, err := io.ReadFull(r, magic[:])
	if err != nil {
		return nil, errors.New("connection reset")
	}
	if bytes.Equal(magic[:], TestnetMagic[:]) != m.Testnet {
		return nil, errors.New("invalid magic")
	}
	// Command, 12 bytes, human-readable
	var cmdBytes [12]byte
	io.ReadFull(r, cmdBytes[:])
	m.Command = string(bytes.TrimRight(cmdBytes[:], "\x00"))
	// Payload length, 4 bytes, little-endian
	var payloadLength uint32
	binary.Read(r, binary.LittleEndian, &payloadLength)
	// Payload checksum, first 4 bytes of hash256(Payload)
	var checksum [4]byte
	io.ReadFull(r, checksum[:])
	// Payload
	m.Payload = make([]byte, payloadLength)
	io.ReadFull(r, m.Payload)

	// verify checksum
	h256 := hash.Hash256(m.Payload)
	if !bytes.Equal(h256[:4], checksum[:]) {
		return nil, errors.New("checksum doesn't match")
	}

	return m, nil
}
