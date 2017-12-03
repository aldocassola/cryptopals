// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package gomd4 implements the MD4 hash algorithm as defined in RFC 1320.
package gomd4

// Size The size of an MD4 checksum in bytes.
const Size = 16

// BlockSize The blocksize of MD4 in bytes.
const BlockSize = 64

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

// GoMd4 represents the partial evaluation of a checksum.
type GoMd4 struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

// Reset resets the hash to initial state
func (d *GoMd4) Reset() {
	d.s[0] = _Init0
	d.s[1] = _Init1
	d.s[2] = _Init2
	d.s[3] = _Init3
	d.nx = 0
	d.len = 0
}

// Reinit reinitializes with given array
func (d *GoMd4) Reinit(data []byte, length uint64) {
	for i := 0; i < 4; i++ {
		d.s[i] = uint32(data[i*4])
		d.s[i] |= uint32(data[i*4+1]) << 8
		d.s[i] |= uint32(data[i*4+2]) << 16
		d.s[i] |= uint32(data[i*4+3]) << 24
	}
	d.nx = 0
	d.len = length
}

// New returns a new hash.Hash computing the MD4 checksum.
func New() *GoMd4 {
	d := new(GoMd4)
	d.Reset()
	return d
}

// Size returns the size
func (d *GoMd4) Size() int { return Size }

// BlockSize returns the size of block
func (d *GoMd4) BlockSize() int { return BlockSize }

func (d *GoMd4) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum appends hash to the given input
func (d *GoMd4) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d0 := new(GoMd4)
	*d0 = *d

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	len := d0.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d0.Write(tmp[0 : 56-len%64])
	} else {
		d0.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d0.Write(tmp[0:8])

	if d0.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d0.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}
