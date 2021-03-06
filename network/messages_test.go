package network

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/VIVelev/btcd/utils"
)

func TestVersionMsgMarshal(t *testing.T) {
	vm := VersionMsg{
		Version:   70015,
		Services:  0,
		Timestamp: 0,
		AddrRecv: NetAddr{
			Services: 0,
			IP:       net.ParseIP("0.0.0.0"),
			Port:     8333,
		},
		AddrSndr: NetAddr{
			Services: 0,
			IP:       net.ParseIP("0.0.0.0"),
			Port:     8333,
		},
		Nonce:     0,
		UserAgent: "/programmingbitcoin:0.1/",
		Height:    0,
		Relay:     false,
	}

	want, _ := hex.DecodeString("7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000")
	b, _ := vm.marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestGetHeadersMsgMarshal(t *testing.T) {
	var sb [32]byte
	b, _ := hex.DecodeString("0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3")
	copy(sb[:], b)

	gh := GetHeadersMsg{
		Version:    70015,
		NumHashes:  1,
		StartBlock: sb,
		EndBlock:   [32]byte{},
	}
	b, _ = gh.marshal()
	want, _ := hex.DecodeString("7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestHeadersMsgUnmarshal(t *testing.T) {
	hm := new(HeadersMsg)
	hm.unmarshal(hex.NewDecoder(strings.NewReader("0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600j")))
	if len(hm.Headers) != 2 {
		t.Errorf("FAIL")
	}
}

func TestFilterloadMsgMarshal(t *testing.T) {
	bf := BloomFilter{
		Size:         10,
		NumHashFuncs: 5,
		Tweak:        99,
	}
	bf.BitField = make([]byte, bf.Size*8)
	bf.Add([]byte("Hello World"))
	bf.Add([]byte("Goodbye!"))
	msg := FilterloadMsg{BloomFilter: bf, Flags: 1}
	want, _ := hex.DecodeString("0a4000600a080000010940050000006300000001")
	b, _ := msg.marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestGetDataMsgMarshal(t *testing.T) {
	gd := new(GetDataMsg)
	block, _ := hex.DecodeString("00000000000000cac712b726e4326e596170574c01a16001692510c44025eb30")
	iv := new(InventoryVector)
	copy(iv.Hash[:], block)
	iv.Type = FilteredBlockDataType
	gd.Add(*iv)
	block, _ = hex.DecodeString("00000000000000beb88910c46f6b442312361c6693a7fb52065b583979844910")
	iv = new(InventoryVector)
	copy(iv.Hash[:], block)
	iv.Type = FilteredBlockDataType
	gd.Add(*iv)

	want, _ := hex.DecodeString("020300000030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000030000001049847939585b0652fba793661c361223446b6fc41089b8be00000000000000")
	b, _ := gd.marshal()
	if !bytes.Equal(b, want) {
		t.Errorf("FAIL")
	}
}

func TestMerkleblockMsgUnmarshal(t *testing.T) {
	mb := new(MerkleblockMsg)
	mb.unmarshal(hex.NewDecoder(strings.NewReader("00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635")))

	if mb.Version != 0x20000000 {
		t.Errorf("FAIL")
	}
	b, _ := hex.DecodeString("df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000")
	copy(b, utils.Reversed(b))
	if !bytes.Equal(mb.PrevBlock[:], b) {
		t.Errorf("FAIL")
	}
	b, _ = hex.DecodeString("ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4")
	copy(b, utils.Reversed(b))
	if !bytes.Equal(mb.MerkleRoot[:], b) {
		t.Errorf("FAIL")
	}
	var timestamp uint32
	binary.Read(hex.NewDecoder(strings.NewReader("dc7c835b")), binary.LittleEndian, &timestamp)
	if mb.Timestamp != timestamp {
		t.Errorf("FAIL")
	}
	b, _ = hex.DecodeString("67d8001a")
	if !bytes.Equal(mb.Bits[:], b) {
		t.Errorf("FAIL")
	}
	b, _ = hex.DecodeString("c157e670")
	if !bytes.Equal(mb.Nonce[:], b) {
		t.Errorf("FAIL")
	}

	var totalTxs uint32
	binary.Read(hex.NewDecoder(strings.NewReader("bf0d0000")), binary.LittleEndian, &totalTxs)
	if mb.TotalTxs != totalTxs {
		t.Errorf("FAIL")
	}
	hexHashes := [10]string{
		"ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a",
		"7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d",
		"34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2",
		"158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba",
		"ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce",
		"f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097",
		"c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d",
		"6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543",
		"d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c",
		"dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261",
	}
	for i := range hexHashes {
		b, _ = hex.DecodeString(hexHashes[i])
		copy(b, utils.Reversed(b))
		if !bytes.Equal(mb.Hashes[i][:], b) {
			t.Errorf("FAIL")
		}
	}
	b, _ = hex.DecodeString("b55635")
	if !bytes.Equal(mb.Flags, b) {
		t.Errorf("FAIL")
	}
}

func TestMerkleblockMsgIsValid(t *testing.T) {
	mb := new(MerkleblockMsg)
	mb.unmarshal(hex.NewDecoder(strings.NewReader("00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635")))
	if v, _ := mb.IsValid(); !v {
		t.Errorf("FAIL")
	}
}
