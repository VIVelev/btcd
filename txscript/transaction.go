package txscript

type Tx struct {
	Version  uint32
	TxIns    []TxIn
	TxOuts   []TxOut
	Locktime uint32
}

type TxIn struct {
	PrevTxId  [32]byte // prev transaction ID: hash256 of prev tx contents
	PrevIndex uint64   // UTXO output index in the prev transaction
	ScriptSig Script   // unlocking script
	Sequence  uint32   // originally intended for "high frequency trades", with locktime
}

type TxOut struct {
	Amount       int    // in units of satoshi (1e-8 of a bitcoin)
	ScriptPubKey Script // locking script
}
