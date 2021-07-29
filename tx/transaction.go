// Implementation of Bitcoin transaction.
// Reference: https://en.bitcoin.it/wiki/Transaction
package tx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/hash"
	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/script"
	"github.com/VIVelev/btcd/utils"
)

const (
	// Sighash Types
	SighashAll = uint32(iota)
	SighashNone
	SighashSingle
)

type Tx struct {
	Version  uint32
	TxIns    []TxIn
	TxOuts   []TxOut
	LockTime uint32

	// Utility, not transmitted over the wire.
	TestNet bool
	SegWit  bool

	// The following are (re)used in SeghashBip143 to fix the O(n^2) hashing problem.
	// The first byte signalizes whether the cache is empty.
	hashPrevoutsCache [33]byte
	hashSequenceCache [33]byte
	hashOutputsCache  [33]byte
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

func (t *Tx) marshalLegacy(sigIndex int) ([]byte, error) {
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
	binary.Write(buf, binary.LittleEndian, t.LockTime)
	// marshal SighashAll, 4 bytes, little-endian, if sigIndex != -1
	if sigIndex != -1 {
		binary.Write(buf, binary.LittleEndian, SighashAll)
	}
	// return bytes
	return buf.Bytes(), nil
}

// SighashLegacy returns the message that needs to get signed for the input with the index.
func (t *Tx) SighashLegacy(index int) ([32]byte, error) {
	b, err := t.marshalLegacy(index)
	return hash.Hash256(b), err
}

// hashPrevouts returns Hash256(<txIn.PrevTxId> + <txIn.PrevIndex> for all inputs)
func (t *Tx) hashPrevouts() (ret [32]byte) {
	if t.hashPrevoutsCache[0] == 0 {
		// the cache is empty
		allPrevouts := make([]byte, 36*len(t.TxIns))
		for i, txIn := range t.TxIns {
			var prevTxId [32]byte
			copy(prevTxId[:], utils.Reversed(txIn.PrevTxId[:]))
			var prevIndex [4]byte
			binary.LittleEndian.PutUint32(prevIndex[:], txIn.PrevIndex)
			copy(allPrevouts[i*36:(i+1)*36], bytes.Join([][]byte{prevTxId[:], prevIndex[:]}, nil))
		}

		h := hash.Hash256(allPrevouts)
		t.hashPrevoutsCache[0] = 1
		copy(t.hashPrevoutsCache[1:], h[:])
	}

	copy(ret[:], t.hashPrevoutsCache[1:])
	return
}

// hashSequence returns Hash256(<txIn.Sequence> for all inputs)
func (t *Tx) hashSequence() (ret [32]byte) {
	if t.hashSequenceCache[0] == 0 {
		// the cache is empty
		allSequence := make([]byte, 4*len(t.TxIns))
		for i, txIn := range t.TxIns {
			binary.LittleEndian.PutUint32(allSequence[i*4:(i+1)*4], txIn.Sequence)
		}

		h := hash.Hash256(allSequence)
		t.hashSequenceCache[0] = 1
		copy(t.hashSequenceCache[1:], h[:])
	}

	copy(ret[:], t.hashSequenceCache[1:])
	return
}

// hashOutputs returns Hash256(<txOut.Marshal()> for all outputs)
func (t *Tx) hashOutputs() (ret [32]byte, err error) {
	if t.hashOutputsCache[0] == 0 {
		// the cache is empty
		var allOutputs []byte
		for _, txOut := range t.TxOuts {
			b, err := txOut.Marshal()
			if err != nil {
				return [32]byte{}, err
			}
			allOutputs = append(allOutputs, b...)
		}

		h := hash.Hash256(allOutputs)
		t.hashOutputsCache[0] = 1
		copy(t.hashOutputsCache[1:], h[:])
	}

	copy(ret[:], t.hashOutputsCache[1:])
	return
}

// SighashBip143 returns the message that needs to get signed for the input with the index.
// Fixes the O(n^2) hashing problem.
// ref: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#Specification
func (t *Tx) SighashBip143(index int, scriptPubKey script.Script, value uint64) ([32]byte, error) {
	var err error
	txIn := t.TxIns[index]
	buf := new(bytes.Buffer)

	// Tx Version, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, t.Version)
	// Tx hashPrevouts, 32 bytes, little-endian
	h := t.hashPrevouts()
	buf.Write(h[:])
	// Tx hashSequence, 32 bytes, little-endian
	h = t.hashSequence()
	buf.Write(h[:])

	// txIn PrevTxId, 32 byte, little-endian
	copy(h[:], utils.Reversed(txIn.PrevTxId[:]))
	buf.Write(h[:])
	// txIn PrevIndex, 4 byte, little-endian
	binary.Write(buf, binary.LittleEndian, txIn.PrevIndex)
	// txIn ScriptPubKey, Script marshalling
	var spk script.Script
	if scriptPubKey != nil {
		spk = scriptPubKey
	} else {
		spk, err = txIn.ScriptPubKey()
		if err != nil {
			return [32]byte{}, err
		}
	}
	if !spk.IsP2WPKH() {
		return [32]byte{}, errors.New("unknown script type")
	}
	var h160 [20]byte
	copy(h160[:], spk.GetBytes(1))
	s := script.NewP2PKHScript(h160)
	b, err := s.Marshal()
	if err != nil {
		return [32]byte{}, err
	}
	buf.Write(b)
	// txIn Value, 8 bytes, little-endian
	var val uint64
	if value != 0 {
		val = value
	} else {
		val, err = txIn.Value()
		if err != nil {
			return [32]byte{}, err
		}
	}
	binary.Write(buf, binary.LittleEndian, val)
	// txIn Sequence, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, txIn.Sequence)

	// Tx hashOutputs, 32 bytes, little-endian
	h, err = t.hashOutputs()
	if err != nil {
		return [32]byte{}, err
	}
	buf.Write(h[:])
	// Tx Locktime, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, t.LockTime)
	// Sighash type, 4 bytes, little-endian
	binary.Write(buf, binary.LittleEndian, SighashAll)

	return hash.Hash256(buf.Bytes()), nil
}

// VerifyInput returns whether the input has a valid signature
func (t *Tx) VerifyInput(index int) (bool, error) {
	in := t.TxIns[index]
	spk, err := in.ScriptPubKey()
	if err != nil {
		return false, err
	}
	var sighash [32]byte
	if spk.IsP2PKH() {
		sighash, err = t.SighashLegacy(index)
	} else if spk.IsP2WPKH() {
		sighash, err = t.SighashBip143(index, nil, 0)
	} else {
		return false, errors.New("unknown script type")
	}
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
	var err error
	// get the signature hash (the message to sign)
	var sighash [32]byte
	if t.SegWit {
		sighash, err = t.SighashBip143(index, nil, 0)
	} else {
		sighash, err = t.SighashLegacy(index)
	}
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
	return t.marshalLegacy(-1)
}

// Unmarshal parses a Tx from the Reader r.
//
// Legacy format:
//     [Version][NumIns][TxIns][NumOuts][TxOuts][LockTime]
// SegWit format:
//	   [Version][Marker][Flag][NumIns][TxIns][NumOuts][TxOuts][Witness][LockTime]
func (t *Tx) Unmarshal(r io.Reader) (*Tx, error) {
	// Version, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &t.Version)

	var numIns, numOuts int
	var hasReadNumOuts bool
	// VarInt number of inputs
	numIns = int(encoding.DecodeVarInt(r).Int64())
	if numIns == 0 {
		var segWitFlag [1]byte
		io.ReadFull(r, segWitFlag[:])
		t.SegWit = segWitFlag[0] == 1
		if t.SegWit {
			numIns = int(encoding.DecodeVarInt(r).Int64())
		} else {
			numOuts = int(segWitFlag[0])
			if numOuts != 0 {
				return nil, errors.New("can't have outputs when there are 0 inputs")
			}
			hasReadNumOuts = true
		}
	}
	// TxIns
	t.TxIns = make([]TxIn, numIns)
	for i := range t.TxIns {
		t.TxIns[i].TestNet = t.TestNet
		t.TxIns[i].Unmarshal(r)
	}
	if !hasReadNumOuts {
		// VarInt number of outputs
		numOuts = int(encoding.DecodeVarInt(r).Int64())
	}
	// TxOuts
	t.TxOuts = make([]TxOut, numOuts)
	for i := range t.TxOuts {
		t.TxOuts[i].Unmarshal(r)
	}

	if t.SegWit {
		// Witness
		for i := range t.TxIns {
			numElements := int(encoding.DecodeVarInt(r).Int64())
			for j := 0; j < numElements; j++ {
				elementLen := int(encoding.DecodeVarInt(r).Int64())
				b := make([]byte, elementLen)
				if elementLen == 0 {
					b = []byte{0}
				} else {
					io.ReadFull(r, b)
				}
				t.TxIns[i].Witness = append(t.TxIns[i].Witness, b)
			}
		}
	}

	// LockTime, 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &t.LockTime)

	return t, nil
}

type TxIn struct {
	PrevTxId  [32]byte      // prev transaction ID: hash256 of prev tx contents
	PrevIndex uint32        // UTXO output index in the prev transaction
	ScriptSig script.Script // unlocking script
	Sequence  uint32        // originally intended for "high frequency trades", with locktime

	// Utility, not transmitted over the wire.
	TestNet bool // whether this tx is on testnet or mainnet

	// SegWit specific
	Witness [][]byte // stack elements
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
	tx, err := Fetch(hex.EncodeToString(in.PrevTxId[:]), in.TestNet, false)
	if err != nil {
		return 0, err
	}
	return tx.TxOuts[in.PrevIndex].Amount, nil
}

// ScriptPubKey returns the ScriptPubKey of the UTXO from the previous transaction
func (in *TxIn) ScriptPubKey() (script.Script, error) {
	tx, err := Fetch(hex.EncodeToString(in.PrevTxId[:]), in.TestNet, false)
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
