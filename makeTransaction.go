package main

import (
	"encoding/hex"
	"fmt"

	"github.com/VIVelev/btcd/crypto/ecdsa"
	"github.com/VIVelev/btcd/crypto/elliptic"
	"github.com/VIVelev/btcd/encoding"
	"github.com/VIVelev/btcd/txscript"
)

func main() {
	priv := ecdsa.GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
	// Use some secret of yours for the passphrase above.
	pub := priv.PublicKey
	address := encoding.Address(&pub, true, true)
	// the last two boolean arguments are:
	//     1) Should I use compressed format for the address? - YES! Space is valuable!
	//     2) Is this address for the testnet or mainnet? - Well, I will use the testnet,
	// because I don't have any spare coins. :)

	fmt.Printf("My Bitcoin address is: %s. Send me some coins!\n", address)

	// Go get some coins! For example from: https://coinfaucet.eu/en/btc-testnet/

	prevTxId := "68389d05ce8c54041dafcf12820d4246f5ca5128b2d414b5317af58a5274d09e"
	prevIndex := 1

	// Now construct the input
	txIn := txscript.TxIn{}
	bytes, _ := hex.DecodeString(prevTxId)
	copy(txIn.PrevTxId[:], bytes)
	txIn.PrevIndex = uint32(prevIndex)
	txIn.Testnet = true

	myTotalCoinsInSatoshi, _ := txIn.Value() // 1 satoshi = 1e-8 bitcoin
	fmt.Printf("I have %d satoshi.\n", myTotalCoinsInSatoshi)
	// I will send 60% of my satoshi to myself. :)
	targetAmount := uint64(0.6 * float64(myTotalCoinsInSatoshi))
	// Lets pay the miners!
	fee := uint64(1500)
	// Calculate the change amount, I will send this back to `address`.
	changeAmount := myTotalCoinsInSatoshi - targetAmount - fee

	// Create the target transaction output
	targetAddress := "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv"
	targetH160 := encoding.DecodeAddress(targetAddress)
	targetScript := txscript.NewP2PKHScript(targetH160)
	targetTxOut := txscript.TxOut{
		Amount:       targetAmount,
		ScriptPubKey: targetScript,
	}

	// Create the change transaction output
	changeH160 := encoding.DecodeAddress(address)
	changeScript := txscript.NewP2PKHScript(changeH160)
	changeTxOut := txscript.TxOut{
		Amount:       changeAmount,
		ScriptPubKey: changeScript,
	}

	// Combine the inputs & outputs in a transaction
	tx := txscript.Tx{
		Version:  1,
		TxIns:    []txscript.TxIn{txIn},
		TxOuts:   []txscript.TxOut{targetTxOut, changeTxOut},
		Locktime: 0,
		Testnet:  true,
	}
	// And sign the inputs please. In this way you verify that the money
	// you are about to spend are, indeed, yours.
	tx.SignInput(0, priv)

	// Now get the transaction's serialization in hex:
	bytes, _ = tx.Marshal()
	fmt.Printf("Tx's Hex: %s\n", hex.EncodeToString(bytes))
}
