// Copyright (C) 2025 CISPA Helmholtz Center for Information Security
// Author: Kevin Morio <kevin.morio@cispa.de>
//
// This file is part of SpecMon.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with program. If not, see <https://www.gnu.org/licenses/>.

package term

import "math/bits"

const (
	hamtBits  = 5
	hamtWidth = 1 << hamtBits
	hamtMask  = hamtWidth - 1
)

type hamtNode struct {
	bitmap  uint32
	entries []hamtEntry
}

type hamtEntry struct {
	key       Term
	value     Term
	child     *hamtNode
	collision *hamtCollision
}

type hamtCollision struct {
	hash    uint64
	entries []hamtLeaf
}

type hamtLeaf struct {
	key   Term
	value Term
}

func (n *hamtNode) get(k Term, hash uint64, shift uint) (Term, bool) {
	if n == nil {
		return nil, false
	}
	bit := hamtBit(hash, shift)
	if n.bitmap&bit == 0 {
		return nil, false
	}
	idx := hamtIndex(n.bitmap, bit)
	entry := n.entries[idx]
	if entry.key != nil {
		if entry.key == k || entry.key.Equal(k) {
			return entry.value, true
		}
		return nil, false
	}
	if entry.collision != nil {
		return entry.collision.get(k)
	}
	return entry.child.get(k, hash, shift+hamtBits)
}

func (n *hamtNode) set(k, v Term, hash uint64, shift uint) (*hamtNode, bool) {
	if n == nil {
		bit := hamtBit(hash, shift)
		return &hamtNode{
			bitmap:  bit,
			entries: []hamtEntry{{key: k, value: v}},
		}, true
	}
	bit := hamtBit(hash, shift)
	idx := hamtIndex(n.bitmap, bit)

	if n.bitmap&bit == 0 {
		return n.insertAt(idx, bit, hamtEntry{key: k, value: v}), true
	}

	entry := n.entries[idx]
	switch {
	case entry.key != nil:
		if entry.key == k || entry.key.Equal(k) {
			if entry.value.Equal(v) {
				return n, false
			}
			return n.updateAt(idx, hamtEntry{key: entry.key, value: v}), false
		}
		entryHash := entry.key.Hash()
		if entryHash == hash {
			collision := newCollision(entryHash, entry.key, entry.value, k, v)
			return n.updateAt(idx, hamtEntry{collision: collision}), true
		}
		child := newSubNodeWithTwo(entry.key, entry.value, entryHash, k, v, hash, shift+hamtBits)
		return n.updateAt(idx, hamtEntry{child: child}), true
	case entry.collision != nil:
		collision, added := entry.collision.set(k, v)
		if collision == entry.collision {
			return n, added
		}
		return n.updateAt(idx, hamtEntry{collision: collision}), added
	case entry.child != nil:
		child, added := entry.child.set(k, v, hash, shift+hamtBits)
		if child == entry.child {
			return n, added
		}
		return n.updateAt(idx, hamtEntry{child: child}), added
	default:
		return n, false
	}
}

func (n *hamtNode) remove(k Term, hash uint64, shift uint) (*hamtNode, bool) {
	if n == nil {
		return nil, false
	}
	bit := hamtBit(hash, shift)
	if n.bitmap&bit == 0 {
		return n, false
	}
	idx := hamtIndex(n.bitmap, bit)
	entry := n.entries[idx]

	switch {
	case entry.key != nil:
		if entry.key == k || entry.key.Equal(k) {
			return n.removeAt(idx, bit), true
		}
		return n, false
	case entry.collision != nil:
		collision, removed := entry.collision.remove(k)
		if !removed {
			return n, false
		}
		if collision == nil || len(collision.entries) == 0 {
			return n.removeAt(idx, bit), true
		}
		if len(collision.entries) == 1 {
			leaf := collision.entries[0]
			return n.updateAt(idx, hamtEntry{key: leaf.key, value: leaf.value}), true
		}
		return n.updateAt(idx, hamtEntry{collision: collision}), true
	case entry.child != nil:
		child, removed := entry.child.remove(k, hash, shift+hamtBits)
		if !removed {
			return n, false
		}
		if child == nil || len(child.entries) == 0 {
			return n.removeAt(idx, bit), true
		}
		if leaf, ok := child.singleLeaf(); ok {
			return n.updateAt(idx, leaf), true
		}
		return n.updateAt(idx, hamtEntry{child: child}), true
	default:
		return n, false
	}
}

func (n *hamtNode) iterate(f func(Term, Term) bool) bool {
	if n == nil {
		return true
	}
	for _, entry := range n.entries {
		switch {
		case entry.key != nil:
			if !f(entry.key, entry.value) {
				return false
			}
		case entry.collision != nil:
			if !entry.collision.iterate(f) {
				return false
			}
		case entry.child != nil:
			if !entry.child.iterate(f) {
				return false
			}
		}
	}
	return true
}

func (n *hamtNode) insertAt(idx int, bit uint32, entry hamtEntry) *hamtNode {
	entries := make([]hamtEntry, len(n.entries)+1)
	copy(entries, n.entries[:idx])
	entries[idx] = entry
	copy(entries[idx+1:], n.entries[idx:])
	return &hamtNode{
		bitmap:  n.bitmap | bit,
		entries: entries,
	}
}

func (n *hamtNode) updateAt(idx int, entry hamtEntry) *hamtNode {
	entries := make([]hamtEntry, len(n.entries))
	copy(entries, n.entries)
	entries[idx] = entry
	return &hamtNode{
		bitmap:  n.bitmap,
		entries: entries,
	}
}

func (n *hamtNode) removeAt(idx int, bit uint32) *hamtNode {
	if len(n.entries) == 1 {
		return nil
	}
	entries := make([]hamtEntry, len(n.entries)-1)
	copy(entries, n.entries[:idx])
	copy(entries[idx:], n.entries[idx+1:])
	return &hamtNode{
		bitmap:  n.bitmap &^ bit,
		entries: entries,
	}
}

func (n *hamtNode) singleLeaf() (hamtEntry, bool) {
	if n == nil || len(n.entries) != 1 {
		return hamtEntry{}, false
	}
	entry := n.entries[0]
	if entry.key != nil {
		return entry, true
	}
	return hamtEntry{}, false
}

func hamtBit(hash uint64, shift uint) uint32 {
	return uint32(1) << ((hash >> shift) & hamtMask)
}

func hamtIndex(bitmap, bit uint32) int {
	return bits.OnesCount32(bitmap & (bit - 1))
}

func newCollision(hash uint64, k1, v1, k2, v2 Term) *hamtCollision {
	return &hamtCollision{
		hash: hash,
		entries: []hamtLeaf{
			{key: k1, value: v1},
			{key: k2, value: v2},
		},
	}
}

func (c *hamtCollision) get(k Term) (Term, bool) {
	if c == nil {
		return nil, false
	}
	for _, entry := range c.entries {
		if entry.key == k || entry.key.Equal(k) {
			return entry.value, true
		}
	}
	return nil, false
}

func (c *hamtCollision) set(k, v Term) (*hamtCollision, bool) {
	for i, entry := range c.entries {
		if entry.key == k || entry.key.Equal(k) {
			if entry.value.Equal(v) {
				return c, false
			}
			entries := make([]hamtLeaf, len(c.entries))
			copy(entries, c.entries)
			entries[i] = hamtLeaf{key: entry.key, value: v}
			return &hamtCollision{hash: c.hash, entries: entries}, false
		}
	}
	entries := make([]hamtLeaf, len(c.entries)+1)
	copy(entries, c.entries)
	entries[len(c.entries)] = hamtLeaf{key: k, value: v}
	return &hamtCollision{hash: c.hash, entries: entries}, true
}

func (c *hamtCollision) remove(k Term) (*hamtCollision, bool) {
	for i, entry := range c.entries {
		if entry.key == k || entry.key.Equal(k) {
			if len(c.entries) == 1 {
				return nil, true
			}
			entries := make([]hamtLeaf, len(c.entries)-1)
			copy(entries, c.entries[:i])
			copy(entries[i:], c.entries[i+1:])
			return &hamtCollision{hash: c.hash, entries: entries}, true
		}
	}
	return c, false
}

func (c *hamtCollision) iterate(f func(Term, Term) bool) bool {
	for _, entry := range c.entries {
		if !f(entry.key, entry.value) {
			return false
		}
	}
	return true
}

func newSubNodeWithTwo(k1, v1 Term, h1 uint64, k2, v2 Term, h2 uint64, shift uint) *hamtNode {
	if h1 == h2 {
		bit := hamtBit(h1, shift)
		return &hamtNode{
			bitmap:  bit,
			entries: []hamtEntry{{collision: newCollision(h1, k1, v1, k2, v2)}},
		}
	}
	bit1 := hamtBit(h1, shift)
	bit2 := hamtBit(h2, shift)
	if bit1 != bit2 {
		entries := make([]hamtEntry, 0, 2)
		if bit1 < bit2 {
			entries = append(entries, hamtEntry{key: k1, value: v1}, hamtEntry{key: k2, value: v2})
		} else {
			entries = append(entries, hamtEntry{key: k2, value: v2}, hamtEntry{key: k1, value: v1})
		}
		return &hamtNode{
			bitmap:  bit1 | bit2,
			entries: entries,
		}
	}
	child := newSubNodeWithTwo(k1, v1, h1, k2, v2, h2, shift+hamtBits)
	return &hamtNode{
		bitmap:  bit1,
		entries: []hamtEntry{{child: child}},
	}
}
