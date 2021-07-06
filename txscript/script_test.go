package txscript

import (
	"bytes"
	"testing"
)

var cmds = stack{
	OP_1,
	OP_2,
	OP_2DUP,
	OP_EQUAL,
	OP_NOT,
	OP_VERIFY,
	OP_SHA1,
	OP_SWAP,
	OP_SHA1,
	OP_EQUAL,
}

var s = new(Script).SetCmds(cmds)

func TestScriptMarshal(t *testing.T) {
	buf, _ := s.Marshal()
	if !bytes.Equal(buf, []byte{10, 81, 82, 110, 135, 145, 105, 167, 124, 167, 135}) {
		t.Errorf("FAIL")
	}
}

func TestScriptUnmarshal(t *testing.T) {
	buf, _ := s.Marshal()
	newS := new(Script).Unmarshal(bytes.NewReader(buf))

	for i := range s.Cmds.Iter() {
		if !s.Cmds.PeekAt(i).Equal(newS.Cmds.PeekAt(i)) {
			t.Errorf("FAIL")
		}
	}
}
