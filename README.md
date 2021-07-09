# btcd

A pure Go from-scratch zero-dependecy implementation of Bitcoin for educational purposes.
It also includes all of the under the hood crypto primitives such as SHA-256, elliptic curves
over finite prime fields math, ECDSA and other.

## What can it do?

Right now it can create and validate transactions such as Pay-to-PubKey-Hash and
all the operations related to it.

## Now you may be asking how can I use `btcd` to create transactions. Well...

### 1) You will need to create your own Bitcoin private key, public key and address.
```golang
// Generate your own private key, public key, and address.
priv := ecdsa.GenerateKey(elliptic.Secp256k1, "vivelev@icloud.comiamfrombetelgeuse")
// Use some secret of yours for the passphrase above.
pub := priv.PublicKey
address := encoding.Address(&pub, true, true)
// the last two boolean arguments are:
//     1) Should I use compressed format for the address? - YES! Space is valuable!
//     2) Is this address for the testnet or mainnet? - Well, I will use the testnet,
// because I don't have any spare coins. :)

fmt.Printf("My Bitcoin address is: %s. Send me some coins!\n", address)
```

### 2) Now go get some testnet coins! Sadly, they aren't worth a dime. :(
I personally use the following faucet: https://coinfaucet.eu/en/btc-testnet/

### 3) Lets construct the input of our transaction.
#### 3.1) You need to get the ID of the transaction that gave you the coins above.
Navigate to https://mempool.space/testnet and search your address using the search bar.
Mine txId was: `68389d05ce8c54041dafcf12820d4246f5ca5128b2d414b5317af58a5274d09e`.

#### 3.2) Also, the index of your output (the one with your address).
Since my address showed up second in the column on the right (the outputs), my index is: `1`.

#### 3.3) Combining it all: Lets build the transaction input!
```golang
// Get the id:
prevTxId := "68389d05ce8c54041dafcf12820d4246f5ca5128b2d414b5317af58a5274d09e"
// Get the index:
prevIndex := 1

// Now construct the input
txIn := txscript.TxIn{}
bytes, _ := hex.DecodeString(prevTxId)
copy(txIn.PrevTxId[:], bytes)
txIn.PrevIndex = uint32(prevIndex)
txIn.Testnet = true
```

### 4) Decide how much coins you want to send me. ;)
You decide how much. Also, don't forget the fee!!! Here is what I did:
```golang
myTotalCoinsInSatoshi, _ := txIn.Value() // 1 satoshi = 1e-8 bitcoin
fmt.Printf("I have %d satoshi.", myTotalCoinsInSatoshi)
// I will send 60% of my satoshi to myself. :)
targetAmount := uint64(0.6 * float64(myTotalCoinsInSatoshi))
// Lets pay the miners!
fee := uint64(1500)
// Calculate the change amount, I will send this back to `address`.
changeAmount := myTotalCoinsInSatoshi - targetAmount - fee
```

### 5) Lets build the transaction output.
I want you to send me the coins to: `mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv`.
Here is how:
```golang
// Create the target transaction output
targetAddress := "mwJn1YPMq7y5F8J3LkC5Hxg9PHyZ5K4cFv"
targetH160 := encoding.DecodeAddress(targetAddress)
targetScript := txscript.NewP2PKHScript(targetH160)
targetTxOut := txscript.TxOut{
    Amount:       targetAmount,
    ScriptPubKey: targetScript,
}
```

### 6) Lets not forget amount the change, that's money!
```golang
// Create the change transaction output
changeH160 := encoding.DecodeAddress(address)
changeScript := txscript.NewP2PKHScript(changeH160)
changeTxOut := txscript.TxOut{
    Amount:       changeAmount,
    ScriptPubKey: changeScript,
}
```

### 7) We are almost done! Now we need to combine the inputs & outputs into a single transaction.
```golang
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
```

### 8) Print the hex of the transaction, so we can broadcast it to the network!
```golang
bytes, _ = tx.Marshal()
fmt.Printf("Tx's Hex: %s\n", hex.EncodeToString(bytes))
```
Now you can navigate to a service like https://live.blockcypher.com/btc-testnet/pushtx/ and
broadcast your transaction to the world! Soon, you will be able to do so directly from btcd.


#### The full source of making a transaction is in [makeTransaction.go](./makeTransaction.go)

## TODO
 - Well, where are the blocks of the blockchain, ha!
 - Bitcoin's p2p protocol, so I can run a (full) node.
 - Maybe something else that I am missing...

## Unit tests
```bash
$ go test ./...
```
