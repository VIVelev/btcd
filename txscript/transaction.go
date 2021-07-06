package txscript

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/VIVelev/btcd/crypto/hash"
	"github.com/VIVelev/btcd/encoding"
)

type TxFetcher struct {
	cache map[string]Tx
}

var txFtchr = TxFetcher{map[string]Tx{}}

func (f *TxFetcher) GetUrl(testnet bool) string {
	if testnet {
		return "https://blockstream.info/testnet/api"
	}
	return "https://blockstream.info/api"
}

func (f *TxFetcher) Fetch(txId string, testnet, fresh bool) (Tx, error) {
	// TODO: Write cache to a local file

	tx, ok := f.cache[txId]
	if fresh || !ok {
		url := fmt.Sprintf("%s/tx/%s/hex", f.GetUrl(testnet), txId)
		resp, err := http.Get(url)
		if err != nil {
			return Tx{}, err
		}
		defer resp.Body.Close()
		tx = Tx{}
		tx.Unmarshal(hex.NewDecoder(resp.Body))
		if tx.Id() != txId {
			return Tx{}, errors.New("TxFetcher: IDs don't match")
		}
		f.cache[txId] = tx
	}
	return tx, nil
}

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

func (t *Tx) Id() string {
	b, err := t.Marshal()
	if err != nil {
		panic(err)
	}
	b32 := hash.Hash256(b)
	return hex.EncodeToString(reverse(b32[:]))
}

// Fee returns the fee of this transaction in satoshi
func (t *Tx) Fee() int {
	var inputSum, outputSum uint64 = 0, 0
	for _, in := range t.TxIns {
		v, err := in.Value()
		if err != nil {
			panic(err)
		}
		inputSum += v
	}
	for _, out := range t.TxOuts {
		outputSum += out.Amount
	}

	if outputSum > inputSum {
		return -int(outputSum - inputSum)
	}
	return int(inputSum - outputSum)
}

func (t *Tx) Marshal() ([]byte, error) {
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
	for _, in := range t.TxIns {
		b, err = in.Marshal()
		if err != nil {
			return nil, err
		}
		buf.Write(b)
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
	// return bytes
	return buf.Bytes(), nil
}

func (t *Tx) Unmarshal(r io.Reader) *Tx {
	// Version is 4 bytes, little-endian
	binary.Read(r, binary.LittleEndian, &t.Version)
	// VarInt number of inputs
	numIns := int(encoding.DecodeVarInt(r).Int64())
	// TxIns
	t.TxIns = make([]TxIn, numIns)
	for i := range t.TxIns {
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
	binary.Read(r, binary.LittleEndian, &t.Locktime)
	// return Tx
	return t
}

type TxIn struct {
	PrevTxId  [32]byte // prev transaction ID: hash256 of prev tx contents
	PrevIndex uint32   // UTXO output index in the prev transaction
	ScriptSig Script   // unlocking script
	Sequence  uint32   // originally intended for "high frequency trades", with locktime
	testnet   bool     // whether this tx is on testnet or mainnet
}

func (in *TxIn) Marshal() ([]byte, error) {
	buf := new(bytes.Buffer)
	// marshal PrevTxId, 32 bytes, little-endian
	buf.Write(reverse(append([]byte{}, in.PrevTxId[:]...)))
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
	io.ReadFull(r, in.PrevTxId[:])
	reverse(in.PrevTxId[:])
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
	tx, err := txFtchr.Fetch(hex.EncodeToString(in.PrevTxId[:]), in.testnet, false)
	if err != nil {
		return 0, err
	}
	return tx.TxOuts[in.PrevIndex].Amount, nil
}

// ScriptPubKey returns the ScriptPubKey of the UTXO from the previous transaction
func (in *TxIn) ScriptPubKey() (Script, error) {
	tx, err := txFtchr.Fetch(hex.EncodeToString(in.PrevTxId[:]), in.testnet, false)
	if err != nil {
		return Script{}, err
	}
	return tx.TxOuts[in.PrevIndex].ScriptPubKey, nil
}

type TxOut struct {
	Amount       uint64 // in units of satoshi (1e-8 of a bitcoin)
	ScriptPubKey Script // locking script
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