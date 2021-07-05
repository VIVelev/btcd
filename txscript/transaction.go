package txscript

import (
	"bytes"
	"encoding/binary"
	"io"
)

func reverse(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

type Tx struct {
	Version  uint32
	TxIns    []TxIn
	TxOuts   []TxOut
	Locktime uint32
}

type TxIn struct {
	PrevTxId  [32]byte // prev transaction ID: hash256 of prev tx contents
	PrevIndex uint32   // UTXO output index in the prev transaction
	ScriptSig Script   // unlocking script
	Sequence  uint32   // originally intended for "high frequency trades", with locktime
}

func (in *TxIn) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// marshal PrevTxId, little-endian
	binary.Write(buf, binary.LittleEndian, in.PrevTxId)
	// marshal PrevIndex, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, in.PrevIndex)
	// marshal ScriptSig
	b, err := in.ScriptSig.Marshal()
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// marshal Sequence, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, in.Sequence)
	// return bytes
	return buf.Bytes(), nil
}

func (in *TxIn) Unmarshal(r io.Reader) *TxIn {
	// PrevTxId is 32 bytes, little-endian
	binary.Read(r, binary.LittleEndian, in.PrevTxId[:])
	// PrevIndex is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &in.PrevIndex)
	// ScriptSig
	in.ScriptSig = *new(Script).Unmarshal(r)
	// Sequence is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &in.Sequence)
	// return TxIn
	return in
}

type TxOut struct {
	Amount       int    // in units of satoshi (1e-8 of a bitcoin)
	ScriptPubKey Script // locking script
}
