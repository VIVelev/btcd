package txscript

import (
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

var (
	tx      Tx
	txBytes []byte
)

func TestMain(m *testing.M) {
	txBytes, _ = hex.DecodeString("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")
	tx = Tx{}
	tx.Unmarshal(bytes.NewReader(txBytes))
	os.Exit(m.Run())
}

func TestUnmarshalVersion(t *testing.T) {
	if tx.Version != 1 {
		t.Errorf("FAIL")
	}
}

func TestUnmarshalInputs(t *testing.T) {
	if len(tx.TxIns) != 1 {
		t.Errorf("FAIL")
	}

	want, _ := hex.DecodeString("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81")
	if !bytes.Equal(tx.TxIns[0].PrevTxId[:], want) {
		t.Errorf("FAIL")
	}
	if tx.TxIns[0].PrevIndex != 0 {
		t.Errorf("FAIL")
	}

	want, _ = hex.DecodeString("6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a")
	b, _ := tx.TxIns[0].ScriptSig.Marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
	if tx.TxIns[0].Sequence != 0xfffffffe {
		t.Errorf("FAIL")
	}
}

func TestUnmarshalOutputs(t *testing.T) {
	if len(tx.TxOuts) != 2 {
		t.Errorf("FAIL")
	}
	if tx.TxOuts[0].Amount != 32454049 {
		t.Errorf("FAIL")
	}
	want, _ := hex.DecodeString("1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac")
	b, _ := tx.TxOuts[0].ScriptPubKey.Marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
	if tx.TxOuts[1].Amount != 10011545 {
		t.Errorf("FAIL")
	}
	want, _ = hex.DecodeString("1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac")
	b, _ = tx.TxOuts[1].ScriptPubKey.Marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestUnmarshalLocktime(t *testing.T) {
	if tx.Locktime != 410393 {
		t.Errorf("FAIL")
	}
}

func TestMarshal(t *testing.T) {
	b, _ := tx.Marshal()
	if !bytes.Equal(b, txBytes) {
		t.Errorf("FAIL")
	}
}

func TestInputValue(t *testing.T) {
	b, _ := hex.DecodeString("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81")
	var txId [32]byte
	copy(txId[:], b)
	in := TxIn{txId, 0, Script{}, 0xffffffff}
	val, err := in.Value(false)
	if err != nil {
		t.Error(err)
	}
	if val != 42505594 {
		t.Errorf("FAIL")
	}
}
