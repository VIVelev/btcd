package network

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/big"
	"net"

	"github.com/VIVelev/btcd/blockchain"
	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/utils"
)

const (
	TxDataType = iota + 1
	BlockDataType
	FilteredBlockDataType
	CompactBlockDataType
)

// When a network address is needed somewhere, this structure is used.
type NetAddr struct {
	Time     uint32 // The Time (version >= 31402). Not present in version message.
	Services uint64 // Same service(s) listed in version.
	IP       net.IP // IPv6 address or IPv4 address.
	Port     uint16 // Port number.
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

// message interface represents the bitcoin's protocol network message
type message interface {
	command() string // A constant. Describes the message type.
	marshal() ([]byte, error)
	unmarshal(r io.Reader) message
}

// When a node creates an outgoing connection, it will immediately advertise its version.
// The remote node will respond with its version. No further communication is possible until
// both peers have exchanged their version.
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

// The verack message is sent in reply to version.
type VerackMsg struct{}

func (va *VerackMsg) command() string {
	return "verack"
}

func (va *VerackMsg) marshal() ([]byte, error) {
	return []byte{0}, nil
}

func (va *VerackMsg) unmarshal(r io.Reader) message {
	return va
}

// Return a headers packet containing the headers of blocks starting right after the last known
// hash in the block locator object, up to EndBlock or 2000 blocks, whichever comes first.
type GetHeadersMsg struct {
	Version    int32    // The protocol version.
	NumHashes  int32    // VarInt. Number of block locator hash entries; can be >1 upon chain split.
	StartBlock [32]byte // Block locator object.
	EndBlock   [32]byte // Hash of last desired block; set to zero for as many blocks as possible.
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

	buf.Write(utils.Reversed(gh.StartBlock[:]))
	buf.Write(utils.Reversed(gh.EndBlock[:]))

	return buf.Bytes(), nil
}

func (gh *GetHeadersMsg) unmarshal(r io.Reader) message {
	// TODO
	return gh
}

// The headers packet returns block headers in response to a getheaders packet.
type HeadersMsg struct {
	Headers []blockchain.Block
}

func (hm *HeadersMsg) command() string {
	return "headers"
}

func (hm *HeadersMsg) marshal() ([]byte, error) {
	return []byte{0}, nil
}

func (hm *HeadersMsg) unmarshal(r io.Reader) message {
	count := encoding.DecodeVarInt(r)
	for i := 0; i < int(count.Int64()); i++ {
		hm.Headers = append(hm.Headers, *new(blockchain.Block).Unmarshal(r))
		// The number of transactions is also given and is always zero if we
		// only request the headers. This is done so that the same code can be
		// used to decode the "block" message, which contains the full block
		// information with all the transactions attached.
		numTxs := encoding.DecodeVarInt(r)
		if numTxs.Sign() != 0 {
			return nil
		}
	}

	return hm
}

// The ping message is sent primarily to confirm that the TCP/IP connection is still valid.
// An error in transmission is presumed to be a closed connection and the address is removed
// as a current peer.
type PingMsg struct {
	Nonce uint64 // Random nonce.
}

func (p *PingMsg) command() string {
	return "ping"
}

func (p *PingMsg) marshal() ([]byte, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], p.Nonce)
	return buf[:], nil
}

func (p *PingMsg) unmarshal(r io.Reader) message {
	binary.Read(r, binary.BigEndian, &p.Nonce)
	return p
}

// The pong message is sent in response to a ping message.
// A pong response is generated using a nonce included in the ping.
type PongMsg struct {
	Nonce uint64 // Nonce from Ping.
}

func (p *PongMsg) command() string {
	return "pong"
}

func (p *PongMsg) marshal() ([]byte, error) {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], p.Nonce)
	return buf[:], nil
}

func (p *PongMsg) unmarshal(r io.Reader) message {
	binary.Read(r, binary.BigEndian, &p.Nonce)
	return p
}

// Upon receiving a filterload command, the remote peer will immediately restrict the
// broadcast transactions it announces (in inv packets) to transactions matching the filter.
type FilterloadMsg struct {
	BloomFilter
	Flags uint8 // A set of flags that control how matched items are added to the filter.
}

func (f *FilterloadMsg) command() string {
	return "filterload"
}

func (f *FilterloadMsg) marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// start with the size of the filter in bytes
	b, err := encoding.EncodeVarInt(big.NewInt(int64(f.Size)))
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// next add the BitField
	b, err = f.bytes()
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// NumHashFuncs, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, f.NumHashFuncs)
	// Tweak, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, f.Tweak)
	// Flag, 1 byte
	buf.WriteByte(byte(f.Flags))

	return buf.Bytes(), nil
}

func (f *FilterloadMsg) unmarshal(r io.Reader) message {
	// TODO
	return f
}

// Inventory vectors are used for notifying other nodes
// about objects they have or data which is being requested.
type InventoryVector struct {
	Type uint32   // Identifies the object type linked to this inventory.
	Hash [32]byte // Hash of the object.
}

func (iv *InventoryVector) marshal() (ret [36]byte) {
	binary.LittleEndian.PutUint32(ret[:4], iv.Type)
	copy(ret[4:], utils.Reversed(iv.Hash[:]))
	return
}

// Packet getdata is used to retrieve the content of a specific object, and is
// usually sent after receiving an inv packet, after filtering known elements.
type GetDataMsg struct {
	Inventory []InventoryVector
}

// Add a new object to the Inventory.
func (gd *GetDataMsg) Add(v InventoryVector) {
	gd.Inventory = append(gd.Inventory, v)
}

func (gd *GetDataMsg) command() string {
	return "getdata"
}

func (gd *GetDataMsg) marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// start with the number of inventory vectors as a varint
	b, err := encoding.EncodeVarInt(big.NewInt(int64(len(gd.Inventory))))
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// marshal each inventory vector
	for _, v := range gd.Inventory {
		b := v.marshal()
		buf.Write(b[:])
	}

	return buf.Bytes(), nil
}

func (gd *GetDataMsg) unmarshal(r io.Reader) message {
	// TODO
	return gd
}

// After a filter has been set, nodes don't merely stop announcing non-matching transactions,
// they can also serve filtered blocks.
type MerkleblockMsg struct {
	blockchain.Block
	TotalTxs uint32     // Number of transactions in the block (including unmatched ones).
	Hashes   [][32]byte // Hashes in depth-first order.
	Flags    []byte     // Flag bits, packed per 8 in a byte, least significant bit first.
}

func (mb *MerkleblockMsg) command() string {
	return "merkleblock"
}

func (mb *MerkleblockMsg) marshal() ([]byte, error) {
	// TODO
	return []byte{0}, nil
}

func (mb *MerkleblockMsg) unmarshal(r io.Reader) message {
	mb.Block.Unmarshal(r)
	// TotalTxs, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &mb.TotalTxs)
	// numHashes, VarInt
	numHashes := encoding.DecodeVarInt(r).Uint64()
	// Hashes
	mb.Hashes = make([][32]byte, numHashes)
	for i := range mb.Hashes {
		// Hash, 32 bytes, little-endian
		io.ReadFull(r, mb.Hashes[i][:])
		copy(mb.Hashes[i][:], utils.Reversed(mb.Hashes[i][:]))
	}
	// lengthFlags, VarInt
	lengthFlags := encoding.DecodeVarInt(r).Uint64()
	// Flags
	mb.Flags = make([]byte, lengthFlags)
	io.ReadFull(r, mb.Flags)

	return mb
}
