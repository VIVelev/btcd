package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/VIVelev/btcd/blockchain"
	"github.com/VIVelev/btcd/network"
)

// partialValidation validates the block headers of the first 40,000 blocks
func partialValidation() {
	// Start with the genesis block
	// https://en.bitcoin.it/wiki/Genesis_block
	previous := new(blockchain.Block).Unmarshal(bytes.NewReader(blockchain.MainGenesisBlockBytes))

	// Now let's crawl the blockchain block headers
	conn, err := net.Dial("tcp", "mainnet.programmingbitcoin.com:8333")
	if err != nil {
		panic(err)
	}
	node := &network.Node{
		Conn:    conn,
		Testnet: false,
		Logging: true,
	}
	if err = node.Handshake(); err != nil {
		panic(err)
	}

	blocks := []*blockchain.Block{previous}
	for i := 0; i < 20; i++ {
		// request the next batch of 2,000 headers
		getheaders := network.GetHeadersMsg{
			Version:    70015,
			NumHashes:  1,
			StartBlock: previous.Id(),
			EndBlock:   "0000000000000000000000000000000000000000000000000000000000000000",
		}
		node.Write(&getheaders)
		msg, err := node.WaitFor("headers")
		if err != nil {
			panic(err)
		}
		headers := msg.(*network.HeadersMsg)

		blocks = append(blocks, headers.Headers...)
		l := len(blocks)
		previous = blocks[l-1]
		fmt.Printf("received another batch of blocks, now have %d\n", l)
	}
	node.Close()
}
