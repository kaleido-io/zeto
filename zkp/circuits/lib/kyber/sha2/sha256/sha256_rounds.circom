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
pragma circom 2.2.2;
  
include "../sha2_common.circom";
include "sha256_compress.circom";
include "sha256_round_const.circom";

//------------------------------------------------------------------------------
// execute `n` rounds of the SHA224 / SHA256 inner loop
// NOTE: hash state is stored as 8 dwords, each little-endian

template SHA2_224_256_rounds(n) {
 
  assert( n >  0  );
  assert( n <= 64 );

  signal input  words[n];            // round words (32-bit words)
  signal input  inp_hash[8][32];     // initial state
  signal output out_hash[8][32];     // final state after n rounds (n <= 64)

  signal  a [n+1][32];
  signal  b [n+1][32];
  signal  c [n+1][32];
  signal  dd[n+1];
  signal  e [n+1][32];
  signal  f [n+1][32];
  signal  g [n+1][32];
  signal  hh[n+1];

  signal round_keys[64];
  component RC = SHA2_224_256_round_keys();
  round_keys <== RC.out;

  a[0] <== inp_hash[0];
  b[0] <== inp_hash[1];
  c[0] <== inp_hash[2];

  e[0] <== inp_hash[4];
  f[0] <== inp_hash[5];
  g[0] <== inp_hash[6];
  
  var sum_dd = 0;
  var sum_hh = 0;
  for(var i=0; i<32; i++) {
    sum_dd  +=  inp_hash[3][i] * (1<<i);  
    sum_hh  +=  inp_hash[7][i] * (1<<i);  
  }
  dd[0] <== sum_dd;
  hh[0] <== sum_hh;

  signal hash_words[8];
  for(var j=0; j<8; j++) {
    var sum = 0;
    for(var i=0; i<32; i++) {
      sum += (1<<i) * inp_hash[j][i];
    }
    hash_words[j] <== sum;
  }

  component compress[n];  

  for(var k=0; k<n; k++) {

    compress[k] = SHA2_224_256_compress_inner();

    compress[k].inp <== words[k];
    compress[k].key <== round_keys[k];

    compress[k].a  <== a [k];
    compress[k].b  <== b [k];
    compress[k].c  <== c [k];
    compress[k].dd <== dd[k];
    compress[k].e  <== e [k];
    compress[k].f  <== f [k];
    compress[k].g  <== g [k];
    compress[k].hh <== hh[k];

    compress[k].out_a  ==> a [k+1];
    compress[k].out_b  ==> b [k+1];
    compress[k].out_c  ==> c [k+1];
    compress[k].out_dd ==> dd[k+1];
    compress[k].out_e  ==> e [k+1];
    compress[k].out_f  ==> f [k+1];
    compress[k].out_g  ==> g [k+1];
    compress[k].out_hh ==> hh[k+1];
  }

  component modulo[8];
  for(var j=0; j<8; j++) {
    modulo[j] = Bits33();
  }

  var sum_a = 0;
  var sum_b = 0;
  var sum_c = 0;
  var sum_e = 0;
  var sum_f = 0;
  var sum_g = 0;
  for(var i=0; i<32; i++) {
    sum_a += (1<<i) * a[n][i];
    sum_b += (1<<i) * b[n][i];
    sum_c += (1<<i) * c[n][i];
    sum_e += (1<<i) * e[n][i];
    sum_f += (1<<i) * f[n][i];
    sum_g += (1<<i) * g[n][i];
  }
  
  modulo[0].inp <== hash_words[0] + sum_a;
  modulo[1].inp <== hash_words[1] + sum_b;
  modulo[2].inp <== hash_words[2] + sum_c;
  modulo[3].inp <== hash_words[3] + dd[n];
  modulo[4].inp <== hash_words[4] + sum_e;
  modulo[5].inp <== hash_words[5] + sum_f;
  modulo[6].inp <== hash_words[6] + sum_g;
  modulo[7].inp <== hash_words[7] + hh[n];

  for(var j=0; j<8; j++) {
    modulo[j].out_bits ==> out_hash[j];
  }

}

// -----------------------------------------------------------------------------
