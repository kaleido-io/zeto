// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package smt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMarkNonEmptySibling(t *testing.T) {
	p := &proof{}
	for i := 0; i < 256; i++ {
		p.MarkNonEmptySibling(uint(i))
	}
	expected := make([]byte, 32)
	for i := 0; i < 32; i++ {
		expected[i] = 0xff
	}
	assert.Equal(t, p.nonEmptySiblings, expected)
}

func TestIsBitOnBigEndian(t *testing.T) {
	p := &proof{}
	expected := make([]byte, 32)
	for i := 0; i < 32; i++ {
		expected[i] = 0xff
	}
	p.nonEmptySiblings = expected
	for i := 0; i < 256; i++ {
		assert.True(t, isBitOnBigEndian(p.nonEmptySiblings, uint(i)))
	}
}

func TestMarkAndCheck(t *testing.T) {
	p := &proof{}
	p.MarkNonEmptySibling(0)
	p.MarkNonEmptySibling(10)
	p.MarkNonEmptySibling(136)
	assert.True(t, p.IsNonEmptySibling(0))
	assert.False(t, p.IsNonEmptySibling(1))
	assert.False(t, p.IsNonEmptySibling(2))
	assert.False(t, p.IsNonEmptySibling(3))
	assert.False(t, p.IsNonEmptySibling(4))
	assert.False(t, p.IsNonEmptySibling(5))
	assert.False(t, p.IsNonEmptySibling(6))
	assert.False(t, p.IsNonEmptySibling(7))
	assert.False(t, p.IsNonEmptySibling(8))
	assert.False(t, p.IsNonEmptySibling(9))
	assert.True(t, p.IsNonEmptySibling(10))
	assert.False(t, p.IsNonEmptySibling(55))
	assert.True(t, p.IsNonEmptySibling(136))
	assert.False(t, p.IsNonEmptySibling(137))
}
