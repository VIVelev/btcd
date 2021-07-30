// Implementation of Bitcoin's Script language.
// Reference: https://en.bitcoin.it/wiki/Script
package script

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/encoding"
)

// Script is simply a slice of commands.
type Script []command

// NewP2PKHScript returns a Pay-to-PubkeyHash Script
func NewP2PKHScript(h160 [20]byte) Script {
	return []command{
		OP_DUP,
		OP_HASH160,
		element(h160[:]),
		OP_EQUALVERIFY,
		OP_CHECKSIG,
	}
}

// IsP2PKH returns whether this follows the:
//     `OP_DUP OP_HASH160 <20 byte hash> OP_EQUALVERIFY OP_CHECKSIG` pattern
func (s *Script) IsP2PKH() bool {
	cmds := *s
	return len(cmds) == 5 && cmds[0] == OP_DUP && cmds[1] == OP_HASH160 &&
		len(cmds[2].(element)) == 20 && cmds[3] == OP_EQUALVERIFY &&
		cmds[4] == OP_CHECKSIG
}

// IsP2WPKH returns whether this follows the:
//     `OP_0 <20 byte hash>` pattern
func (s *Script) IsP2WPKH() bool {
	cmds := *s
	return len(cmds) == 2 && cmds[0] == OP_0 &&
		len(cmds[1].(element)) == 20
}

func (s *Script) Add(cmds ...command) Script {
	return append(*s, cmds...)
}

func (s *Script) AddBytes(b ...[]byte) Script {
	els := make([]command, len(b))
	for i := range b {
		els[i] = element(b[i])
	}
	return s.Add(els...)
}

func (s *Script) GetBytes(index int) []byte {
	el := (*s)[index].(element)
	buf := make([]byte, len(el))
	copy(buf, el)
	return buf
}

func (s *Script) copy() Script {
	return s.Add()
}

func (s *Script) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	for _, cmd := range *s {
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
	// TODO: verify command length and command type
	*s = *new(Script)
	length := int(encoding.DecodeVarInt(r).Int64())
	count := 0

	readElement := func(n int) element {
		el := make(element, n)
		io.ReadFull(r, el)
		count += n
		return el
	}

	for count < length {
		var current opcode
		binary.Read(r, binary.LittleEndian, &current)
		count += 1

		// push commands, interpreting opcodes 1-77
		if 1 <= current && current <= 75 {
			// elements of size [1, 75] bytes
			*s = append(*s, readElement(int(current)))
		} else if current == 76 {
			// OP_PUSHDATA1: elements of size [76, 255] bytes
			var elementLength uint8
			binary.Read(r, binary.LittleEndian, &elementLength)
			count += 1
			*s = append(*s, readElement(int(elementLength)))
		} else if current == 77 {
			// OP_PUSHDATA2: elements of size [256, 520] bytes
			var elementLength uint16
			binary.Read(r, binary.LittleEndian, &elementLength)
			count += 2
			*s = append(*s, readElement(int(elementLength)))
		} else {
			// represents an opcode, add it (as int)
			*s = append(*s, current)
		}
	}

	return s
}

func (s *Script) Eval(sighash []byte, witness [][]byte) bool {
	stack, altstack, cmds := new(stack), new(stack), s.copy()

	for len(cmds) > 0 {
		cmd := cmds[0]
		cmds = cmds[1:]
		switch cmd := cmd.(type) {
		case opcode:
			if !OpcodeFunctions[cmd](stack, altstack, cmds, sighash) {
				return false
			}
		case element:
			stack.Push(cmd)

			// witness program version 0 rule
			// if stack cmds are: OP_0 <20 byte hash> this is p2wpkh
			if len(*stack) == 2 && (*stack)[0] == OP_0 && len((*stack)[1].(element)) == 20 {
				_, c := stack.Pop()
				var h160 [20]byte
				copy(h160[:], c.(element))
				stack.Pop() // pop the OP_0
				cmds = cmds.AddBytes(witness...)
				cmds = cmds.Add(NewP2PKHScript(h160)...)
			}
		}
	}

	if len(*stack) == 0 {
		return false
	}
	_, c := stack.Pop()
	el := c.(element)
	return decodeNum(el) != 0
}
