package tx

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
)

var cache map[string]Tx

func init() {
	cache = make(map[string]Tx, 10) // 10 seems cool
}

func getUrl(testnet bool) string {
	if testnet {
		return "https://mempool.space/testnet/api"
	}
	return "https://mempool.space/api"
}

func Fetch(txId string, testnet, fresh bool) (Tx, error) {
	// TODO: Write cache to a local file

	tx, ok := cache[txId]
	if fresh || !ok {
		url := fmt.Sprintf("%s/tx/%s/hex", getUrl(testnet), txId)
		resp, err := http.Get(url)
		if err != nil {
			return Tx{}, err
		}
		defer resp.Body.Close()
		tx = Tx{}
		tx.TestNet = testnet
		tx.Unmarshal(hex.NewDecoder(resp.Body))
		id, err := tx.Id()
		if err != nil {
			return Tx{}, err
		}
		if id != txId {
			return Tx{}, errors.New("TxFetcher: IDs don't match")
		}
		cache[txId] = tx
	}
	return tx, nil
}
