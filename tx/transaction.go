// Implementation of Bitcoin transaction.
// Reference: https://en.bitcoin.it/wiki/Transaction
package tx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/hash"
	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/script"
	"github.com/VIVelev/btcd/utils"
)

type Tx struct {
	Version  uint32
	TxIns    []TxIn
	TxOuts   []TxOut
	Locktime uint32
	Testnet  bool
}

func (t *Tx) Id() (string, error) {
	b, err := t.Marshal()
	if err != nil {
		return "", err
	}
	b32 := hash.Hash256(b)
	return hex.EncodeToString(utils.Reversed(b32[:])), nil
}

// Fee returns the fee of this transaction in satoshi
func (t *Tx) Fee() (int, error) {
	var inputSum, outputSum uint64 = 0, 0
	for _, in := range t.TxIns {
		v, err := in.Value()
		if err != nil {
			return 0, err
		}
		inputSum += v
	}
	for _, out := range t.TxOuts {
		outputSum += out.Amount
	}

	if outputSum > inputSum {
		return -int(outputSum - inputSum), nil
	}
	return int(inputSum - outputSum), nil
}

func (t *Tx) marshal(sigIndex int) ([]byte, error) {
	buf := new(bytes.Buffer)
	// marshal Version, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, t.Version)
	// EncodeVarInt on the number of inputs
	b, err := encoding.EncodeVarInt(big.NewInt(int64(len(t.TxIns))))
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// marshal TxIns
	if sigIndex == -1 {
		for _, in := range t.TxIns {
			b, err = in.Marshal()
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
	} else {
		for i, in := range t.TxIns {
			b, err = in.marshalScriptOverride(i == sigIndex)
			if err != nil {
				return nil, err
			}
			buf.Write(b)
		}
	}
	// EncodeVarInt on the number of outputs
	b, err = encoding.EncodeVarInt(big.NewInt(int64(len(t.TxOuts))))
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// marshal TxOuts
	for _, out := range t.TxOuts {
		b, err = out.Marshal()
		if err != nil {
			return nil, err
		}
		buf.Write(b)
	}
	// marshal Locktime, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, t.Locktime)
	// marshal SIGHASH_ALL, 4 bytes, little-endian, if sigIndex != -1
	if sigIndex != -1 {
		sighashAll := uint32(1)
		binary.Write(buf, binary.LittleEndian, sighashAll)
	}
	// return bytes
	return buf.Bytes(), nil
}

// Sighash returns the message that needs to get signed for the input with the index
func (t *Tx) Sighash(index int) ([32]byte, error) {
	b, err := t.marshal(index)
	return hash.Hash256(b), err
}

// VerifyInput returns whether the input has a valid signature
func (t *Tx) VerifyInput(index int) (bool, error) {
	in := t.TxIns[index]
	spk, err := in.ScriptPubKey()
	if err != nil {
		return false, err
	}
	sighash, err := t.Sighash(index)
	if err != nil {
		return false, err
	}
	combinedScript := in.ScriptSig.Add(spk...)
	return combinedScript.Eval(sighash[:]), nil
}

// Verify returns whether this transaction is valid
func (t *Tx) Verify() (bool, error) {
	fee, err := t.Fee()
	if err != nil {
		return false, err
	}
	if fee < 0 {
		return false, nil
	}

	for i := range t.TxIns {
		ok, err := t.VerifyInput(i)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	return true, nil
}

// SignInput signs the input with the index using the private key
func (t *Tx) SignInput(index int, priv *ecdsa.PrivateKey) (bool, error) {
	// get the signature hash (the message to sign)
	sighash, err := t.Sighash(index)
	if err != nil {
		return false, err
	}
	// get DER signature
	der := priv.Sign(sighash[:]).Marshal()
	// append the SIGHASH_ALL (1) to der
	sig := append(der, 0x01)
	// calculate SEC pubkey
	sec := priv.PublicKey.MarshalCompressed()
	// initialize a new ScriptSig
	scriptSig := new(script.Script).AddBytes(sig, sec)
	// update input's ScriptSig
	t.TxIns[index].ScriptSig = scriptSig

	return t.VerifyInput(index)
}

func (t *Tx) Marshal() ([]byte, error) {
	return t.marshal(-1)
}

func (t *Tx) Unmarshal(r io.Reader) *Tx {
	var hasGarbage = false

	// Version is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &t.Version)
	// VarInt number of inputs
	numIns := int(encoding.DecodeVarInt(r).Int64())
	if numIns == 0 {
		hasGarbage = true
		r.Read(make([]byte, 1)) // garbage byte
		numIns = int(encoding.DecodeVarInt(r).Int64())
	}
	// TxIns
	t.TxIns = make([]TxIn, numIns)
	for i := range t.TxIns {
		t.TxIns[i].Testnet = t.Testnet
		t.TxIns[i].Unmarshal(r)
	}
	// VarInt number of outputs
	numOuts := int(encoding.DecodeVarInt(r).Int64())
	// TxOuts
	t.TxOuts = make([]TxOut, numOuts)
	for i := range t.TxOuts {
		t.TxOuts[i].Unmarshal(r)
	}
	// Locktime is 4 bytes, little-endian
	if hasGarbage {
		b, _ := io.ReadAll(r)
		t.Locktime = binary.LittleEndian.Uint32(b[len(b)-4:])
	} else {
		binary.Read(r, binary.LittleEndian, &t.Locktime)
	}
	// return Tx
	return t
}

type TxIn struct {
	PrevTxId  [32]byte      // prev transaction ID: hash256 of prev tx contents
	PrevIndex uint32        // UTXO output index in the prev transaction
	ScriptSig script.Script // unlocking script
	Sequence  uint32        // originally intended for "high frequency trades", with locktime
	Testnet   bool          // whether this tx is on testnet or mainnet
}

func (in *TxIn) marshal(n int) ([]byte, error) {
	buf := new(bytes.Buffer)
	// marshal PrevTxId, 32 bytes, little-endian
	buf.Write(utils.Reversed(append([]byte{}, in.PrevTxId[:]...)))
	// marshal PrevIndex, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, in.PrevIndex)
	var b []byte
	var err error
	switch n {
	case -1:
		// marshal ScriptSig
		b, err = in.ScriptSig.Marshal()
		if err != nil {
			return nil, err
		}
	case 0:
		// marshal empty Script
		b, err = new(script.Script).Marshal()
		if err != nil {
			return nil, err
		}
	case 1:
		// marshal ScriptPubKey instead of ScriptSig
		spk, err := in.ScriptPubKey()
		if err != nil {
			return nil, err
		}
		b, err = spk.Marshal()
		if err != nil {
			return nil, err
		}
	}
	buf.Write(b)
	// marshal Sequence, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, in.Sequence)
	// return bytes
	return buf.Bytes(), nil
}

func (in *TxIn) marshalScriptOverride(pubkeyOverride bool) ([]byte, error) {
	if pubkeyOverride {
		return in.marshal(1)
	}

	return in.marshal(0)
}

func (in *TxIn) Marshal() ([]byte, error) {
	return in.marshal(-1)
}

func (in *TxIn) Unmarshal(r io.Reader) *TxIn {
	// PrevTxId is 32 bytes, little-endian
	io.ReadFull(r, in.PrevTxId[:])
	copy(in.PrevTxId[:], utils.Reversed(in.PrevTxId[:]))
	// PrevIndex is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &in.PrevIndex)
	// ScriptSig
	in.ScriptSig.Unmarshal(r)
	// Sequence is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &in.Sequence)
	// return TxIn
	return in
}

// Value returns the Amount of the UTXO from the previous transaction
func (in *TxIn) Value() (uint64, error) {
	tx, err := Fetch(hex.EncodeToString(in.PrevTxId[:]), in.Testnet, false)
	if err != nil {
		return 0, err
	}
	return tx.TxOuts[in.PrevIndex].Amount, nil
}

// ScriptPubKey returns the ScriptPubKey of the UTXO from the previous transaction
func (in *TxIn) ScriptPubKey() (script.Script, error) {
	tx, err := Fetch(hex.EncodeToString(in.PrevTxId[:]), in.Testnet, false)
	if err != nil {
		return script.Script{}, err
	}
	return tx.TxOuts[in.PrevIndex].ScriptPubKey, nil
}

type TxOut struct {
	Amount       uint64        // in units of satoshi (1e-8 of a bitcoin)
	ScriptPubKey script.Script // locking script
}

func (out *TxOut) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// marshal Amount, 8 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, out.Amount)
	// marshal ScriptPubKey
	b, err := out.ScriptPubKey.Marshal()
	if err != nil {
		return nil, err
	}
	buf.Write(b)
	// return bytes
	return buf.Bytes(), nil
}

func (out *TxOut) Unmarshal(r io.Reader) *TxOut {
	// Amount is 8 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &out.Amount)
	// ScriptPubKey
	out.ScriptPubKey.Unmarshal(r)
	// return TxOut
	return out
}
