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

const { expect } = require('chai');
const { groth16 } = require('snarkjs');
const {
  genKeypair,
  formatPrivKeyForBabyJub,
  stringifyBigInts,
} = require('maci-crypto');
const {
  Merkletree,
  InMemoryDB,
  str2Bytes,
  ZERO_HASH,
} = require('@iden3/js-merkletree');
const {
  Poseidon,
  newSalt,
  loadCircuit,
  newEncryptionNonce,
  kycHash,
} = require('../index.js');
const { loadProvingKeys } = require('./utils.js');

const SMT_HEIGHT_UTXO = 64;
const SMT_HEIGHT_IDENTITY = 10;
const poseidonHash = Poseidon.poseidon4;
const poseidonHash2 = Poseidon.poseidon2;
const poseidonHash3 = Poseidon.poseidon3;

describe('main circuit tests for Zeto fungible tokens with encryption and anonymity using nullifiers with KYC', () => {
  let circuit, provingKeyFile, verificationKey, smtAlice, smtKYC, smtBob;

  const Alice = {};
  const Bob = {};
  let senderPrivateKey;

  before(async () => {
    circuit = await loadCircuit('anon_enc_nullifier_kyc');
    ({ provingKeyFile, verificationKey } = loadProvingKeys(
      'anon_enc_nullifier_kyc'
    ));

    let keypair = genKeypair();
    Alice.privKey = keypair.privKey;
    Alice.pubKey = keypair.pubKey;
    senderPrivateKey = formatPrivKeyForBabyJub(Alice.privKey);

    keypair = genKeypair();
    Bob.privKey = keypair.privKey;
    Bob.pubKey = keypair.pubKey;

    // initialize the local storage for Alice to manage her UTXOs in the Spart Merkle Tree
    const storage1 = new InMemoryDB(str2Bytes('alice'));
    smtAlice = new Merkletree(storage1, true, SMT_HEIGHT_UTXO);

    // initialize the local storage for Bob to manage his UTXOs in the Spart Merkle Tree
    const storage2 = new InMemoryDB(str2Bytes('bob'));
    smtBob = new Merkletree(storage2, true, SMT_HEIGHT_UTXO);

    // initialize the local storage for the sender to manage identities in the Spart Merkle Tree
    const storage3 = new InMemoryDB(str2Bytes('kyc'));
    smtKYC = new Merkletree(storage3, true, SMT_HEIGHT_IDENTITY);

    // calculate the identity hash for Alice
    const identity1 = poseidonHash2(Alice.pubKey);
    await smtKYC.add(identity1, identity1);

    // calculate the identity hash for Bob
    const identity2 = poseidonHash2(Bob.pubKey);
    await smtKYC.add(identity2, identity2);
  });

  it('should generate a valid proof that can be verified successfully', async () => {
    const inputValues = [32, 40];
    const outputValues = [20, 52];

    // create two input UTXOs, each has their own salt, but same owner
    const senderPrivateKey = formatPrivKeyForBabyJub(Alice.privKey);
    const salt1 = newSalt();
    const input1 = poseidonHash([
      BigInt(inputValues[0]),
      salt1,
      ...Alice.pubKey,
    ]);
    const salt2 = newSalt();
    const input2 = poseidonHash([
      BigInt(inputValues[1]),
      salt2,
      ...Alice.pubKey,
    ]);
    const inputCommitments = [input1, input2];

    // create the nullifiers for the input UTXOs
    const nullifier1 = poseidonHash3([
      BigInt(inputValues[0]),
      salt1,
      senderPrivateKey,
    ]);
    const nullifier2 = poseidonHash3([
      BigInt(inputValues[1]),
      salt2,
      senderPrivateKey,
    ]);
    const nullifiers = [nullifier1, nullifier2];

    // calculate the root of the SMT
    await smtAlice.add(input1, input1);
    await smtAlice.add(input2, input2);

    // generate the merkle proof for the inputs
    const proof1 = await smtAlice.generateCircomVerifierProof(
      input1,
      ZERO_HASH
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      input2,
      ZERO_HASH
    );
    const utxosRoot = proof1.root.bigInt();

    // create two output UTXOs, they share the same salt, and different owner
    const salt3 = newSalt();
    const output1 = poseidonHash([
      BigInt(outputValues[0]),
      salt3,
      ...Bob.pubKey,
    ]);
    const salt4 = newSalt();
    const output2 = poseidonHash([
      BigInt(outputValues[1]),
      salt4,
      ...Alice.pubKey,
    ]);
    const outputCommitments = [output1, output2];

    // generate the merkle proof for the transacting identities
    const proof3 = await smtKYC.generateCircomVerifierProof(
      kycHash(Alice.pubKey),
      ZERO_HASH
    );
    const proof4 = await smtKYC.generateCircomVerifierProof(
      kycHash(Bob.pubKey),
      ZERO_HASH
    );
    const identitiesRoot = proof3.root.bigInt();

    const encryptionNonce = newEncryptionNonce();
    const encryptInputs = stringifyBigInts({
      encryptionNonce,
    });

    const startTime = Date.now();
    const witness = await circuit.calculateWTNSBin(
      {
        nullifiers,
        inputCommitments,
        inputValues,
        inputSalts: [salt1, salt2],
        inputOwnerPrivateKey: senderPrivateKey,
        utxosRoot,
        utxosMerkleProof: [
          proof1.siblings.map((s) => s.bigInt()),
          proof2.siblings.map((s) => s.bigInt()),
        ],
        enabled: [1, 1],
        identitiesRoot,
        identitiesMerkleProof: [
          proof3.siblings.map((s) => s.bigInt()),
          proof4.siblings.map((s) => s.bigInt()),
          proof3.siblings.map((s) => s.bigInt()),
        ],
        outputCommitments,
        outputValues,
        outputSalts: [salt3, salt4],
        outputOwnerPublicKeys: [Bob.pubKey, Alice.pubKey],
        ...encryptInputs,
      },
      true
    );

    const { proof, publicSignals } = await groth16.prove(
      provingKeyFile,
      witness
    );
    console.log('Proving time: ', (Date.now() - startTime) / 1000, 's');

    const success = await groth16.verify(verificationKey, publicSignals, proof);
    // console.log('nullifiers', nullifiers);
    // console.log('inputCommitments', inputCommitments);
    // console.log('outputCommitments', outputCommitments);
    // console.log('utxo root', proof1.root.bigInt());
    // console.log('identitiesRoot', proof3.root.bigInt());
    // console.log('encryptionNonce', encryptionNonce);
    // console.log('publicSignals', publicSignals);
    expect(success, true);
  }).timeout(600000);
});
