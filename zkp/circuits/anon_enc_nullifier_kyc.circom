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
pragma circom 2.1.4;

include "./lib/check-positive.circom";
include "./lib/check-hashes.circom";
include "./lib/check-sum.circom";
include "./lib/check-nullifiers.circom";
include "./lib/check-smt-proof.circom";
include "./lib/ecdh.circom";
include "./lib/encrypt.circom";
include "./node_modules/circomlib/circuits/babyjub.circom";

// This version of the circuit performs the following operations:
// - derive the sender's public key from the sender's private key
// - check the input and output commitments match the expected hashes
// - check the input and output values sum to the same amount
// - perform encryption of the receiver's output UTXO value and salt
// - check the nullifiers are derived from the input commitments and the sender's private key
// - check the nullifiers are included in the Merkle tree
// - check the owner public keys for inputs and outputs are included in the identities merkle tree
template Zeto(nInputs, nOutputs, nUTXOSMTLevels, nIdentitiesSMTLevels) {
  signal input nullifiers[nInputs];
  signal input inputCommitments[nInputs];
  signal input inputValues[nInputs];
  signal input inputSalts[nInputs];
  // must be properly hashed and trimmed to be compatible with the BabyJub curve.
  // Reference: https://github.com/iden3/circomlib/blob/master/test/babyjub.js#L103
  signal input inputOwnerPrivateKey;
  signal input utxosRoot;
  signal input utxosMerkleProof[nInputs][nUTXOSMTLevels];
  signal input enabled[nInputs];
  signal input identitiesRoot;
  signal input identitiesMerkleProof[nOutputs + 1][nIdentitiesSMTLevels];
  signal input outputCommitments[nOutputs];
  signal input outputValues[nOutputs];
  signal input outputOwnerPublicKeys[nOutputs][2];
  signal input outputSalts[nOutputs];
  signal input encryptionNonce;

  // the output for a 2-element input (value and salt) encryption is a 4-element array
  signal output cipherText[4];

  // derive the sender's public key from the secret input
  // for the sender's private key. This step demonstrates
  // the sender really owns the private key for the input
  // UTXOs
  var inputOwnerPublicKey[2];
  component pub = BabyPbk();
  pub.in <== inputOwnerPrivateKey;
  inputOwnerPublicKey[0] = pub.Ax;
  inputOwnerPublicKey[1] = pub.Ay;
  var inputOwnerPublicKeys[nInputs][2];
  for (var i = 0; i < nInputs; i++) {
    inputOwnerPublicKeys[i][0] = inputOwnerPublicKey[0];
    inputOwnerPublicKeys[i][1] = inputOwnerPublicKey[1];
  }

  component checkPositives = CheckPositive(nOutputs);
  checkPositives.outputValues <== outputValues;

  component checkInputHashes = CheckHashes(nInputs);
  checkInputHashes.commitments <== inputCommitments;
  checkInputHashes.values <== inputValues;
  checkInputHashes.salts <== inputSalts;
  checkInputHashes.ownerPublicKeys <== inputOwnerPublicKeys;

  component checkOutputHashes = CheckHashes(nOutputs);
  checkOutputHashes.commitments <== outputCommitments;
  checkOutputHashes.values <== outputValues;
  checkOutputHashes.salts <== outputSalts;
  checkOutputHashes.ownerPublicKeys <== outputOwnerPublicKeys;

  component checkNullifiers = CheckNullifiers(nInputs);
  checkNullifiers.nullifiers <== nullifiers;
  checkNullifiers.values <== inputValues;
  checkNullifiers.salts <== inputSalts;
  checkNullifiers.ownerPrivateKey <== inputOwnerPrivateKey;

  component checkSum = CheckSum(nInputs, nOutputs);
  checkSum.inputValues <== inputValues;
  checkSum.outputValues <== outputValues;

  // With the above steps, we demonstrated that the nullifiers
  // are securely bound to the input commitments. Now we need to
  // demonstrate that the input commitments belong to the Sparse
  // Merkle Tree with the root `root`.
  component checkUTXOSMTProof = CheckSMTProof(nInputs, nUTXOSMTLevels);
  checkUTXOSMTProof.root <== utxosRoot;
  checkUTXOSMTProof.merkleProof <== utxosMerkleProof;
  checkUTXOSMTProof.enabled <== enabled;
  checkUTXOSMTProof.leafNodeIndexes <== inputCommitments;

  // Then, we need to check that the owner public keys
  // for the inputs and outputs are included in the identities
  // Sparse Merkle Tree with the root `identitiesRoot`.
  var ownerPublicKeyHashes[nOutputs + 1];
  component hash1 = Poseidon(2);
  hash1.inputs[0] <== inputOwnerPublicKey[0];
  hash1.inputs[1] <== inputOwnerPublicKey[1];
  ownerPublicKeyHashes[0] = hash1.out;

  component hashes[nOutputs];
  var identitiesMTPCheckEnabled[nOutputs + 1];
  identitiesMTPCheckEnabled[0] = 1;
  for (var i = 0; i < nOutputs; i++) {
    hashes[i] = Poseidon(2);
    hashes[i].inputs[0] <== outputOwnerPublicKeys[i][0];
    hashes[i].inputs[1] <== outputOwnerPublicKeys[i][1];
    ownerPublicKeyHashes[i+1] = hashes[i].out;
    identitiesMTPCheckEnabled[i+1] = 1;
  }

  component checkIdentitiesSMTProof = CheckSMTProof(nOutputs + 1, nIdentitiesSMTLevels);
  checkIdentitiesSMTProof.root <== identitiesRoot;
  checkIdentitiesSMTProof.merkleProof <== identitiesMerkleProof;
  checkIdentitiesSMTProof.enabled <== identitiesMTPCheckEnabled;
  checkIdentitiesSMTProof.leafNodeIndexes <== ownerPublicKeyHashes;

  // generate shared secret
  var sharedSecret[2];
  component ecdh = Ecdh();
  ecdh.privKey <== inputOwnerPrivateKey;
  // our circuit requires that the output UTXO for the receiver must be the first in the array
  ecdh.pubKey[0] <== outputOwnerPublicKeys[0][0];
  ecdh.pubKey[1] <== outputOwnerPublicKeys[0][1];
  sharedSecret[0] = ecdh.sharedKey[0];
  sharedSecret[1] = ecdh.sharedKey[1];

  // encrypt the value for the receiver
  component encrypt = SymmetricEncrypt(2);
  // our circuit requires that the output UTXO for the receiver must be the first in the array
  encrypt.plainText[0] <== outputValues[0];
  encrypt.plainText[1] <== outputSalts[0];
  encrypt.key <== sharedSecret;
  encrypt.nonce <== encryptionNonce;
  encrypt.cipherText[0] ==> cipherText[0];
  encrypt.cipherText[1] ==> cipherText[1];
  encrypt.cipherText[2] ==> cipherText[2];
  encrypt.cipherText[3] ==> cipherText[3];
}

component main { public [ nullifiers, outputCommitments, encryptionNonce, utxosRoot, identitiesRoot, enabled ] } = Zeto(2, 2, 64, 10);