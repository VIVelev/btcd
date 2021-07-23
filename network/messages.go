package network

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"

	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/utils"
)

// When a network address is needed somewhere, this structure is used.
type NetAddr struct {
	Time     uint32 // The Time (version >= 31402). Not present in version message.
	Services uint64 // Same service(s) listed in version.
	IP       net.IP // IPv6 address or IPv4 address.
	Port     uint16 // Port numbet.
}

func (na *NetAddr) marshal() (ret [30]byte) {
	binary.LittleEndian.PutUint32(ret[:4], na.Time)
	binary.LittleEndian.PutUint64(ret[4:12], na.Services)
	copy(ret[12:28], na.IP.To16())
	binary.BigEndian.PutUint16(ret[28:], na.Port)
	return
}

func (na *NetAddr) marshalVersion() (ret [26]byte) {
	b := na.marshal()
	copy(ret[:], b[4:])
	return
}

type message interface {
	command() string
	marshal() ([]byte, error)
	unmarshal(r io.Reader) message
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

func (vm *VersionMsg) command() string {
	return "version"
}

func (vm *VersionMsg) marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// Version, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Version)
	// Services, 8 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Services)
	// Timestamp, 8 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, vm.Timestamp)
	// AddrRecv, 26 bytes
	b := vm.AddrRecv.marshalVersion()
	buf.Write(b[:])
	// AddrSndr, 26 bytes
	b = vm.AddrSndr.marshalVersion()
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

func (vm *VersionMsg) unmarshal(r io.Reader) message {
	// TODO
	return vm
}

type VerackMsg struct{}

func (va *VerackMsg) command() string {
	return "verack"
}

func (va *VerackMsg) marshal() ([]byte, error) {
	return []byte(""), nil
}

func (va *VerackMsg) unmarshal(r io.Reader) message {
	return va
}

type GetHeadersMsg struct {
	Version    int32  // The protocol version.
	NumHashes  int32  // VarInt. Number of block locator hash entries; can be >1 upon chain split.
	StartBlock string // Block locator object. [32]byte
	EndBlock   string // Hash of last desired block; set to zero for as many blocks as possible.
}

func (gh *GetHeadersMsg) command() string {
	return "getheaders"
}

func (gh *GetHeadersMsg) marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, gh.Version)
	b, err := encoding.EncodeVarInt(big.NewInt(int64(gh.NumHashes)))
	if err != nil {
		return nil, err
	}
	buf.Write(b)

	if len(gh.StartBlock) != 64 {
		return nil, errors.New("StartBlock must be of len 64 (256 bits)")
	}
	b, err = hex.DecodeString(gh.StartBlock)
	if err != nil {
		return nil, err
	}
	buf.Write(utils.Reverse(b))
	if len(gh.EndBlock) != 64 {
		return nil, errors.New("EndBlock must be of len 64 (256 bits)")
	}
	b, err = hex.DecodeString(gh.EndBlock)
	if err != nil {
		return nil, err
	}
	buf.Write(utils.Reverse(b))

	return buf.Bytes(), nil
}

func (gh *GetHeadersMsg) unmarshal(r io.Reader) message {
	// TODO
	return gh
}
