package txscript

import "bytes"

type operation func(st, altst stack, cmds []command, sighash []byte) bool
type opcode uint8
type element []byte

func (op opcode) Equal(other command) bool {
	x := other.(opcode)
	return op == x
}

func (op opcode) String() string {
	return OpcodeNames[op]
}

func (el element) Equal(other command) bool {
	x := other.(element)
	return bytes.Equal(el, x)
}

func (el element) String() string {
	return string(el)
}

const (
	//
	// Constants:
	OP_0 = opcode(iota)
	// 1-75: serve as elements
	OP_PUSHDATA1 = opcode(iota + 75)
	OP_PUSHDATA2
	OP_PUSHDATA4
	OP_1NEGATE
	// 80: reserved
	OP_1 = opcode(iota + 76)
	OP_2
	OP_3
	OP_4
	OP_5
	OP_6
	OP_7
	OP_8
	OP_9
	OP_10
	OP_11
	OP_12
	OP_13
	OP_14
	OP_15
	OP_16
	//
	// Flow control:
	OP_NOP
	// 98: reserved
	OP_IF = opcode(iota + 77)
	OP_NOTIF
	// 101: reserved
	// 102: reserved
	OP_ELSE = opcode(iota + 79)
	OP_ENDIF
	OP_VERIFY
	OP_RETURN
	//
	// Stack:
	OP_TOALTSTACK
	OP_FROMALTSTACK
	OP_2DROP
	OP_2DUP
	OP_3DUP
	OP_2OVER
	OP_2ROT
	OP_2SWAP
	OP_IFDUP
	OP_DEPTH
	OP_DROP
	OP_DUP
	OP_NIP
	OP_OVER
	OP_PICK
	OP_ROLL
	OP_ROT
	OP_SWAP
	OP_TUCK
	//
	// Splice:
	// 126-129: disabled
	OP_SIZE = opcode(iota + 83)
	//
	// Bitwise logic:
	// 131-134: disabled
	OP_EQUAL = opcode(iota + 87)
	OP_EQUALVERIFY
	// 137: reserved
	// 138: reserved
	//
	// Arithmetic:
	OP_1ADD = opcode(iota + 89)
	OP_1SUB
	// 141: disabled
	// 142: disabled
	OP_NEGATE = opcode(iota + 91)
	OP_ABS
	OP_NOT
	OP_0NOTEQUAL
	OP_ADD
	OP_SUB
	// 149-153: disabled
	OP_BOOLAND = opcode(iota + 96)
	OP_BOOLOR
	OP_NUMEQUAL
	OP_NUMEQUALVERIFY
	OP_NUMNOTEQUAL
	OP_LESSTHAN
	OP_GREATERTHAN
	OP_LESSTHANOREQUAL
	OP_GREATERTHANOREQUAL
	OP_MIN
	OP_MAX
	OP_WITHIN
	//
	// Crypto:
	OP_RIPEMD160
	OP_SHA1
	OP_SHA256
	OP_HASH160
	OP_HASH256
	OP_CODESEPARATOR
	OP_CHECKSIG
	OP_CHECKSIGVERIFY
	OP_CHECKMULTISIG
	OP_CHECKMULTISIGVERIFY
	//
	// NOP:
	OP_NOP1
	//
	// Locktime:
	OP_CHECKLOCKTIMEVERIFY // previously OP_NOP2
	OP_CHECKSEQUENCEVERIFY // previouslu OP_NOP3
	//
	// NOP:
	OP_NOP4
	OP_NOP5
	OP_NOP6
	OP_NOP7
	OP_NOP8
	OP_NOP9
	OP_NOP10
	//
	// Those are all the OPs as of 2021.
)

var OpcodeFunctions = map[opcode]operation{
	// 0: op0,
	// 76: opPushdata1,
	// 77: opPushdata2,
	// 78: opPushdata4,
	// 79:  op1negate,
	// 81:  op1,
	// 82:  op2,
	// 83:  op3,
	// 84:  op4,
	// 85:  op5,
	// 86:  op6,
	// 87:  op7,
	// 88:  op8,
	// 89:  op9,
	// 90:  op10,
	// 91:  op11,
	// 92:  op12,
	// 93:  op13,
	// 94:  op14,
	// 95:  op15,
	// 96:  op16,
	// 97:  opNop,
	// 99:  opIf,
	// 100: opNotif,
	// 103: opElse,
	// 104: opEndif,
	// 105: opVerify,
	// 106: opReturn,
	// 107: opToaltstack,
	// 108: opFromaltstack,
	// 109: op2drop,
	// 110: op2dup,
	// 111: op3dup,
	// 112: op2over,
	// 113: op2rot,
	// 114: op2swap,
	// 115: opIfdup,
	// 116: opDepth,
	// 117: opDrop,
	// 118: opDup,
	// 119: opNip,
	// 120: opOver,
	// 121: opPick,
	// 122: opRoll,
	// 123: opRot,
	// 124: opSwap,
	// 125: opTuck,
	// 130: opSize,
	// 135: opEqual,
	// 136: opEqualverify,
	// 139: op1add,
	// 140: op1sub,
	// 143: opNegate,
	// 144: opAbs,
	// 145: opNot,
	// 146: op0notequal,
	// 147: opAdd,
	// 148: opSub,
	// 154: opBooland,
	// 155: opBoolor,
	// 156: opNumequal,
	// 157: opNumequalverify,
	// 158: opNumnotequal,
	// 159: opLessthan,
	// 160: opGreaterthan,
	// 161: opLessthanorequal,
	// 162: opGreaterthanorequal,
	// 163: opMin,
	// 164: opMax,
	// 165: opWithin,
	// 166: opRipemd160,
	// 167: opSha1,
	// 168: opSha256,
	// 169: opHash160,
	// 170: opHash256,
	// 172: opChecksig,
	// 173: opChecksigverify,
	// 174: opCheckmultisig,
	// 175: opCheckmultisigverify,
	// 176: opNop,
	// 177: opChecklocktimeverify,
	// 178: opChecksequenceverify,
	// 179: opNop,
	// 180: opNop,
	// 181: opNop,
	// 182: opNop,
	// 183: opNop,
	// 184: opNop,
	// 185: opNop,
}

var OpcodeNames = map[opcode]string{
	//
	// Constants:
	OP_0: "OP_0",
	// 1-75: serve as elements
	OP_PUSHDATA1: "OP_PUSHDATA1",
	OP_PUSHDATA2: "OP_PUSHDATA2",
	OP_PUSHDATA4: "OP_PUSHDATA4",
	OP_1NEGATE:   "OP_1NEGATE",
	// 80: reserved
	81: "OP_1",
	82: "OP_2",
	83: "OP_3",
	84: "OP_4",
	85: "OP_5",
	86: "OP_6",
	87: "OP_7",
	88: "OP_8",
	89: "OP_9",
	90: "OP_10",
	91: "OP_11",
	92: "OP_12",
	93: "OP_13",
	94: "OP_14",
	95: "OP_15",
	96: "OP_16",
	//
	// Flow control:
	97: "OP_NOP",
	// 98: reserved
	99:  "OP_IF",
	100: "OP_NOTIF",
	// 101: reserved
	// 102: reserved
	103: "OP_ELSE",
	104: "OP_ENDIF",
	105: "OP_VERIFY",
	106: "OP_RETURN",
	//
	// Stack:
	107: "OP_TOALTSTACK",
	108: "OP_FROMALTSTACK",
	109: "OP_2DROP",
	110: "OP_2DUP",
	111: "OP_3DUP",
	112: "OP_2OVER",
	113: "OP_2ROT",
	114: "OP_2SWAP",
	115: "OP_IFDUP",
	116: "OP_DEPTH",
	117: "OP_DROP",
	118: "OP_DUP",
	119: "OP_NIP",
	120: "OP_OVER",
	121: "OP_PICK",
	122: "OP_ROLL",
	123: "OP_ROT",
	124: "OP_SWAP",
	125: "OP_TUCK",
	//
	// Splice:
	// 126-129: disabled
	130: "OP_SIZE",
	//
	// Bitwise logic:
	// 131-134: disabled
	135: "OP_EQUAL",
	136: "OP_EQUALVERIFY",
	// 137: reserved
	// 138: reserved
	//
	// Arithmetic:
	139: "OP_1ADD",
	140: "OP_1SUB",
	// 141: disabled
	// 142: disabled
	143: "OP_NEGATE",
	144: "OP_ABS",
	145: "OP_NOT",
	146: "OP_0NOTEQUAL",
	147: "OP_ADD",
	148: "OP_SUB",
	// 149-153: disabled
	154: "OP_BOOLAND",
	155: "OP_BOOLOR",
	156: "OP_NUMEQUAL",
	157: "OP_NUMEQUALVERIFY",
	158: "OP_NUMNOTEQUAL",
	159: "OP_LESSTHAN",
	160: "OP_GREATERTHAN",
	161: "OP_LESSTHANOREQUAL",
	162: "OP_GREATERTHANOREQUAL",
	163: "OP_MIN",
	164: "OP_MAX",
	165: "OP_WITHIN",
	//
	// Crypto:
	166: "OP_RIPEMD160",
	167: "OP_SHA1",
	168: "OP_SHA256",
	169: "OP_HASH160",
	170: "OP_HASH256",
	171: "OP_CODESEPARATOR",
	172: "OP_CHECKSIG",
	173: "OP_CHECKSIGVERIFY",
	174: "OP_CHECKMULTISIG",
	175: "OP_CHECKMULTISIGVERIFY",
	//
	// NOP:
	176: "OP_NOP1",
	//
	// Locktime:
	177: "OP_CHECKLOCKTIMEVERIFY", // previously OP_NOP2
	178: "OP_CHECKSEQUENCEVERIFY", // previouslu OP_NOP3
	//
	// NOP:
	179: "OP_NOP4",
	180: "OP_NOP5",
	181: "OP_NOP6",
	182: "OP_NOP7",
	183: "OP_NOP8",
	184: "OP_NOP9",
	185: "OP_NOP10",
	//
	// Those are all the OPs as of 2021.
}
