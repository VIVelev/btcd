package network

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNewMerkleTree(t *testing.T) {
	tree := newMerkleTree(9)
	if len(tree.nodes[0]) != 1 {
		t.Errorf("FAIL")
	}
	if len(tree.nodes[1]) != 2 {
		t.Errorf("FAIL")
	}
	if len(tree.nodes[2]) != 3 {
		t.Errorf("FAIL")
	}
	if len(tree.nodes[3]) != 5 {
		t.Errorf("FAIL")
	}
	if len(tree.nodes[4]) != 9 {
		t.Errorf("FAIL")
	}
}

func TestPopulate1(t *testing.T) {
	hexHashes := [16]string{
		"9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
		"5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
		"82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
		"507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
		"a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
		"bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
		"ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
		"457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
		"7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
		"b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
		"9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
		"b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
		"b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
		"c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
		"c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
		"f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
	}

	tree := newMerkleTree(16)
	var hashes [16][32]byte
	for i := range hashes {
		h, _ := hex.DecodeString(hexHashes[i])
		copy(hashes[i][:], h)
	}
	var flagBits [31]byte
	for i := range flagBits {
		flagBits[i] = 1
	}
	err := tree.populate(hashes[:], flagBits[:])
	if err != nil {
		t.Error(err)
	}
	root, _ := hex.DecodeString("597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1")
	b := tree.root().hash
	if !bytes.Equal(b[:], root) {
		t.Errorf("FAIL")
	}
}

func TestPopulate2(t *testing.T) {
	hexHashes := [5]string{
		"42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e",
		"94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4",
		"959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953",
		"a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2",
		"62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577",
	}

	tree := newMerkleTree(5)
	var hashes [5][32]byte
	for i := range hashes {
		h, _ := hex.DecodeString(hexHashes[i])
		copy(hashes[i][:], h)
	}
	var flagBits [11]byte
	for i := range flagBits {
		flagBits[i] = 1
	}
	err := tree.populate(hashes[:], flagBits[:])
	if err != nil {
		t.Error(err)
	}
	root, _ := hex.DecodeString("a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab")
	b := tree.root().hash
	if !bytes.Equal(b[:], root) {
		t.Errorf("FAIL")
	}
}
