package script

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// command can be either a opcode or an element
type command interface {
	fmt.Stringer
	Equal(other command) bool
}

type opcode uint8
type element []byte

func (op opcode) Equal(other command) bool {
	x := other.(opcode)
	return op == x
}

func (op opcode) String() string {
	return OpcodeNames[op]
}

func (el element) Equal(other command) bool {
	x := other.(element)
	return bytes.Equal(el, x)
}

func (el element) String() string {
	return hex.EncodeToString(el)
}
