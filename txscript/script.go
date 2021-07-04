package txscript

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/encoding"
)

type Script struct {
	Cmds []interface{}
}

type opcode uint8
type element []byte

func (s *Script) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, cmd := range s.Cmds {
		switch cmd := cmd.(type) {
		case opcode: // if cmd is an integer, it's an opcode
			binary.Write(buf, binary.LittleEndian, cmd)
		case element: // otherwise, this is an element
			length := len(cmd)
			// for large lengths, we have to use a pushdata opcode
			if length <= 75 {
				binary.Write(buf, binary.LittleEndian, uint8(length))
			} else if 76 <= length && length <= 0xff {
				// 76 is pushdata1
				binary.Write(buf, binary.LittleEndian, uint8(76))
				binary.Write(buf, binary.LittleEndian, uint8(length))
			} else if 0x100 <= length && length <= 520 {
				// 77 is pushdata2
				binary.Write(buf, binary.LittleEndian, uint8(77))
				binary.Write(buf, binary.LittleEndian, uint16(length))
			}
			buf.Write(cmd)
		default:
			return nil, errors.New("the command is too long")
		}
	}

	encodedLen, err := encoding.EncodeVarInt(big.NewInt(int64(buf.Len())))
	if err != nil {
		return nil, err
	}
	return append(encodedLen, buf.Bytes()...), nil
}

func (s *Script) Unmarshal(r io.Reader) *Script {
	length := int(encoding.DecodeVarInt(r).Int64())
	cmds := make([]interface{}, length)
	count := 0

	readElement := func(n int) []byte {
		el := make(element, n)
		n, _ = r.Read(el)
		count += n
		return el
	}

	for count < length {
		var current opcode
		binary.Read(r, binary.LittleEndian, current)
		count += 1

		// push commands onto stack, elements as bytes or ops as integers
		if 1 <= current && current <= 75 {
			// elements of size [1, 75] bytes
			cmds = append(cmds, readElement(int(current)))
		} else if current == 76 {
			// pushdata1: elements of size [76, 255] bytes
			dataLength := encoding.DecodeVarInt(r).Int64()
			cmds = append(cmds, readElement(int(dataLength)))
		} else if current == 77 {
			dataLength := encoding.DecodeVarInt(r).Int64()
			cmds = append(cmds, readElement(int(dataLength)))
		} else {
			// represents an opcode, add it (as int)
			cmds = append(cmds, current)
		}
	}

	s.Cmds = cmds
	return s
}
