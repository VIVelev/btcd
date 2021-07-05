package txscript

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/encoding"
)

// command can be either a opcode or an element
type command interface {
	Equal(other command) bool
}

type Script struct {
	Cmds []command
}

func (s *Script) SetCmds(cmds []command) *Script {
	s.Cmds = cmds
	return s
}

func (s *Script) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)

	for _, cmd := range s.Cmds {
		switch cmd := cmd.(type) {
		case opcode:
			binary.Write(buf, binary.LittleEndian, cmd)
		case element:
			length := len(cmd)
			// for large lengths, we have to use a pushdata opcode
			if length <= 75 {
				binary.Write(buf, binary.LittleEndian, opcode(length))
			} else if 76 <= length && length <= 0xff {
				// 76 is OP_PUSHDATA1
				binary.Write(buf, binary.LittleEndian, opcode(76))
				binary.Write(buf, binary.LittleEndian, uint8(length))
			} else if 0x100 <= length && length <= 520 {
				// 77 is OP_PUSHDATA2
				binary.Write(buf, binary.LittleEndian, opcode(77))
				binary.Write(buf, binary.LittleEndian, uint16(length))
			} else {
				return nil, errors.New("Script.Marshal: the command is too long")
			}
			buf.Write(cmd)
		default:
			return nil, errors.New("Script.Marshal: unrecognized command")
		}
	}

	encodedLen, err := encoding.EncodeVarInt(big.NewInt(int64(buf.Len())))
	if err != nil {
		return nil, err
	}
	return append(encodedLen, buf.Bytes()...), nil
}

func (s *Script) Unmarshal(r io.Reader) *Script {
	var cmds []command
	length := int(encoding.DecodeVarInt(r).Int64())
	count := 0

	readElement := func(n int) element {
		el := make(element, n)
		n, _ = r.Read(el)
		count += n
		return el
	}

	for count < length {
		var current opcode
		binary.Read(r, binary.LittleEndian, current)
		count += 1

		// push commands, interpreting opcodes 1-77
		if 1 <= current && current <= 75 {
			// elements of size [1, 75] bytes
			cmds = append(cmds, readElement(int(current)))
		} else if current == 76 {
			// OP_PUSHDATA1: elements of size [76, 255] bytes
			var elementLength uint8
			binary.Read(r, binary.LittleEndian, elementLength)
			count += 1
			cmds = append(cmds, readElement(int(elementLength)))
		} else if current == 77 {
			// OP_PUSHDATA2: elements of size [256, 520] bytes
			var elementLength uint16
			binary.Read(r, binary.LittleEndian, elementLength)
			count += 2
			cmds = append(cmds, readElement(int(elementLength)))
		} else {
			// represents an opcode, add it (as int)
			cmds = append(cmds, current)
		}
	}

	s.Cmds = cmds
	return s
}
