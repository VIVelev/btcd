package network

import (
	"bytes"
	"errors"
	"math"

	"github.com/VIVelev/btcd/crypto/hash"
)

type merkleNode struct {
	hash  [32]byte
	depth int
	index int
}

func merkleParent(l, r merkleNode) (p merkleNode) {
	p = merkleNode{}
	var cat [64]byte
	copy(cat[:32], l.hash[:])
	copy(cat[32:], r.hash[:])
	p.hash = hash.Hash256(cat[:])
	p.depth = l.depth - 1
	p.index = l.index / 2
	return
}

func (n *merkleNode) isEmpty() bool {
	empty := [32]byte{}
	return bytes.Equal(n.hash[:], empty[:])
}

func (n *merkleNode) up() {
	n.depth -= 1
	n.index /= 2
}

func (n *merkleNode) left() {
	n.depth += 1
	n.index *= 2
}

func (n *merkleNode) right() {
	n.left()
	n.index += 1
}

type merkleTree struct {
	numLeaves int
	maxDepth  int
	nodes     [][]merkleNode
}

func newMerkleTree(numLeaves int) merkleTree {
	tree := merkleTree{}
	tree.numLeaves = numLeaves
	tree.maxDepth = int(math.Ceil(math.Log2(float64(numLeaves))))
	tree.nodes = make([][]merkleNode, tree.maxDepth+1)
	for d := 0; d <= tree.maxDepth; d++ {
		n := int(math.Ceil(float64(numLeaves) / math.Pow(2, float64(tree.maxDepth-d))))
		tree.nodes[d] = make([]merkleNode, n)
	}
	return tree
}

func (t *merkleTree) root() merkleNode {
	return t.nodes[0][0]
}

func (t *merkleTree) setNode(n merkleNode) {
	t.nodes[n.depth][n.index] = n
}

func (t *merkleTree) getNode(n merkleNode) merkleNode {
	return t.nodes[n.depth][n.index]
}

func (t *merkleTree) getLeftOf(n merkleNode) merkleNode {
	return t.nodes[n.depth+1][n.index*2]
}

func (t *merkleTree) getRightOf(n merkleNode) merkleNode {
	return t.nodes[n.depth+1][n.index*2+1]
}

func (t *merkleTree) hasRightOf(n merkleNode) bool {
	return len(t.nodes[n.depth+1]) > n.index*2+1
}

func (t *merkleTree) isLeaf(n merkleNode) bool {
	return n.depth == t.maxDepth
}

// The flag bits inform where the hashes go using depth-first ordering.
// The rules for the flag bits are:
// 1. If the node’s value is given in the hashes field, the flag bit is 0.
// 2. If the node's value is to be calculated by the light client, the flag bit is 1.
// 3. If the node is a leaf node and is a transaction of interest, the flag is 1 and
// the node’s value is also given in the hashes field. These are the items proven to
// be included in the Merkle tree.
func (t *merkleTree) populate(flagBits []byte, hashes [][32]byte) error {
	node := merkleNode{} // this node is used to traverse (DFS) the tree
	for {
		// consume a flag
		f := flagBits[0]
		flagBits = flagBits[1:]
	BACKTRACK: // backtracking must skip flag bit consumption
		if r := t.root(); !r.isEmpty() {
			break
		}

		if f == 0 || (f == 1 && t.isLeaf(node)) {
			// we have the hash in hashes
			node.hash = hashes[0]
			hashes = hashes[1:]
			// set the node
			t.setNode(node)
			// move to the parent (backtrack)
			node.up()
			goto BACKTRACK
		} else {
			// peek left child
			leftChild := t.getLeftOf(node)
			if leftChild.isEmpty() {
				node.left()
			} else {
				if t.hasRightOf(node) {
					// peek right child
					rightChild := t.getRightOf(node)
					if rightChild.isEmpty() {
						node.right()
					} else {
						// make merkle parent of left and right; backtrack
						t.setNode(merkleParent(leftChild, rightChild))
						node.up()
						goto BACKTRACK
					}
				} else {
					// make merkle parent of two left; backtrack
					t.setNode(merkleParent(leftChild, leftChild))
					node.up()
					goto BACKTRACK
				}
			}
		}
	}

	if len(flagBits) != 0 {
		return errors.New("flagBits not all consumed")
	}
	if len(hashes) != 0 {
		return errors.New("hashes not all consumed")
	}
	return nil
}
