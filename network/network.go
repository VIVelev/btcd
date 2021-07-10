// package network implements the Bitcoin peer-to-peer network protocol.
// reference: https://en.bitcoin.it/wiki/Protocol_documentation
package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/crypto/hash"
	"github.com/VIVelev/btcd/encoding"
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

type messageType interface{}

func MessageTypeToCommand(mt messageType) string {
	switch mt.(type) {
	case VersionMsg:
		return "version"
	default:
		return ""
	}
}

// When a network address is needed somewhere, this structure is used.
type NetAddr struct {
	Time     uint32   // The Time (version >= 31402). Not present in version message.
	Services uint64   // Same service(s) listed in version.
	IPv6v4   [16]byte // IPv6 address or IPv4 address.
	Port     uint16   // Port numbet.
}

func (na *NetAddr) Marshal() (ret [30]byte) {
	binary.LittleEndian.PutUint32(ret[:4], na.Time)
	binary.LittleEndian.PutUint64(ret[4:12], na.Services)
	copy(ret[12:28], na.IPv6v4[:])
	binary.BigEndian.PutUint16(ret[28:], na.Port)
	return
}

func (na *NetAddr) MarshalVersion() (ret [26]byte) {
	b := na.Marshal()
	copy(ret[:], b[4:])
	return
}

type VersionMsg struct {
	Version   int32   // Identifies protocol version being used by the node.
	Services  uint64  // Bitfield of features to be enabled for this connection.
	Timestamp int64   // Standard UNIX timestamp in seconds.
	AddrRecv  NetAddr // The network address of the node receiving this message.
	AddrSndr  NetAddr // The network address of the node sending this message. (can be ignored)
	Nonce     uint64  // Randomly generated every time. Used to detect connections to self.
	UserAgent string  // User Agent identifies the software being run.
	Height    int32   // The last block received by the sending node.
	Relay     bool    // Whether the remote peer should announce relayed tx, see BIP 0037.
}

func (vm *VersionMsg) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// Version, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Version)
	// Services, 8 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Services)
	// Timestamp, 8 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Timestamp)
	// AddrRecv, 26 bytes
	b := vm.AddrRecv.MarshalVersion()
	buf.Write(b[:])
	// AddrSndr, 26 bytes
	b = vm.AddrSndr.MarshalVersion()
	buf.Write(b[:])
	// Nonce, 8 bytes, big-endian
	binary.Write(buf, binary.BigEndian, vm.Nonce)
	// UserAgent, variable string, so varint first
	length, err := encoding.EncodeVarInt(big.NewInt(int64(len(vm.UserAgent))))
	if err != nil {
		return nil, err
	}
	buf.Write(length)
	buf.Write([]byte(vm.UserAgent))
	// Height, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Height)
	// Relay, boolean
	if vm.Relay {
		buf.WriteByte(0x01)
	} else {
		buf.WriteByte(0x00)
	}
	return buf.Bytes(), nil
}
