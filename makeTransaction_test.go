package main

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/elliptic"
	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/script"
	"github.com/VIVelev/btcd/tx"
)

func TestMakeTransaction(t *testing.T) {
	priv := ecdsa.GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	pub := priv.PublicKey
	address := encoding.Address(&pub, true, true)

	prevTxId := "68389d05ce8c54041dafcf12820d4246f5ca5128b2d414b5317af58a5274d09e"
	prevIndex := 1

	txIn := tx.TxIn{}
	b, _ := hex.DecodeString(prevTxId)
	copy(txIn.PrevTxId[:], b)
	txIn.PrevIndex = uint32(prevIndex)
	txIn.Testnet = true

	myTotalCoinsInSatoshi, _ := txIn.Value() // 1 satoshi = 1e-8 bitcoin
	targetAmount := uint64(0.6 * float64(myTotalCoinsInSatoshi))
	fee := uint64(1500)
	changeAmount := myTotalCoinsInSatoshi - targetAmount - fee

	targetAddress := "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv"
	targetH160, _ := encoding.AddressToPubKeyHash(targetAddress)
	targetScript := script.NewP2PKHScript(targetH160)
	targetTxOut := tx.TxOut{
		Amount:       targetAmount,
		ScriptPubKey: targetScript,
	}

	changeH160, _ := encoding.AddressToPubKeyHash(address)
	changeScript := script.NewP2PKHScript(changeH160)
	changeTxOut := tx.TxOut{
		Amount:       changeAmount,
		ScriptPubKey: changeScript,
	}

	transaction := tx.Tx{
		Version:  1,
		TxIns:    []tx.TxIn{txIn},
		TxOuts:   []tx.TxOut{targetTxOut, changeTxOut},
		Locktime: 0,
		Testnet:  true,
	}

	transaction.SignInput(0, priv)

	want, _ := hex.DecodeString("01000000019ed074528af57a31b514d4b22851caf546420d8212cfaf1d04548cce059d3868010000006b483045022100dd3c597790d17f0c98001f19b6952c2dafcc33f501293c890602fc7a2496e72702203468787c7668dde25d268cc7c5a20cc74ffb02defc0d2307a176c40674bc3a1201210335cbf18f4cd05242e649e09f0298122015ef3d4b3b8fe34b2b72508c100051810000000002eb470900000000001976a914ad346f8eb57dee9a37981716e498120ae80e44f788ac172a0600000000001976a914e1a49130622510dc1b408ff9d93728f3271c361d88ac00000000")
	b, _ = transaction.Marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}
