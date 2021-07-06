package encoding

import (
	"encoding/binary"
	"errors"
	"io"
	"math/big"
)

func EncodeVarInt(i *big.Int) ([]byte, error) {
	if i.Sign() == -1 {
		return nil, errors.New("EncodeVarInt: integer shouldn't be negative")
	}

	// string is hex representation of a number
	isLessThan := func(s string) bool {
		n, _ := new(big.Int).SetString(s, 16)
		return i.Cmp(n) == -1
	}

	if isLessThan("fd") {
		return []byte{byte(i.Uint64())}, nil
	} else if isLessThan("10000") {
		buf := make([]byte, 3)
		buf[0] = 0xfd
		binary.LittleEndian.PutUint16(buf[1:], uint16(i.Uint64()))
		return buf, nil
	} else if isLessThan("100000000") {
		buf := make([]byte, 5)
		buf[0] = 0xfe
		binary.LittleEndian.PutUint32(buf[1:], uint32(i.Uint64()))
		return buf, nil
	} else if isLessThan("10000000000000000") {
		buf := make([]byte, 9)
		buf[0] = 0xff
		binary.LittleEndian.PutUint64(buf[1:], i.Uint64())
		return buf, nil
	} else {
		return nil, errors.New("EncodeVarInt: integer too large")
	}
}

func DecodeVarInt(r io.Reader) *big.Int {
	var i uint8
	binary.Read(r, nil, &i)
	switch i {
	case 0xfd:
		var n uint16
		binary.Read(r, binary.LittleEndian, &n)
		return new(big.Int).SetUint64(uint64(n))
	case 0xfe:
		var n uint32
		binary.Read(r, binary.LittleEndian, &n)
		return new(big.Int).SetUint64(uint64(n))
	case 0xff:
		var n uint64
		binary.Read(r, binary.LittleEndian, &n)
		return new(big.Int).SetUint64(n)
	default:
		return new(big.Int).SetUint64(uint64(i))
	}
}
