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

import { ethers, network } from 'hardhat';
import { ContractTransactionReceipt, Signer, BigNumberish } from 'ethers';
import { expect } from 'chai';
import {
  loadCircuit,
  poseidonDecrypt,
  encodeProof,
  newEncryptionNonce,
  kycHash,
} from 'zeto-js';
import { groth16 } from 'snarkjs';
import { genEcdhSharedKey, stringifyBigInts } from 'maci-crypto';
import { Merkletree, InMemoryDB, str2Bytes } from '@iden3/js-merkletree';
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  newNullifier,
  doMint,
  ZERO_UTXO,
  parseUTXOEvents,
  parseRegistryEvents,
} from './lib/utils';
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
} from './utils';
import { deployZeto } from './lib/deploy';

describe('Zeto based fungible token with anonymity using nullifiers and encryption with KYC', function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let unregistered: User;
  let erc20: any;
  let zeto: any;
  let utxo100: UTXO;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let _utxo3: UTXO;
  let utxo4: UTXO;
  let utxo6: UTXO;
  let utxo7: UTXO;
  let withdrawChangeUTXO: UTXO;
  let circuit: any, provingKey: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;
  let smtKyc: Merkletree;

  before(async function () {
    if (network.name !== 'hardhat') {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c, e] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);
    unregistered = await newUser(e);

    ({ deployer, zeto, erc20 } = await deployZeto('Zeto_AnonEncNullifierKyc'));

    const tx2 = await zeto.connect(deployer).register(Alice.babyJubPublicKey);
    const result1 = await tx2.wait();
    const tx3 = await zeto.connect(deployer).register(Bob.babyJubPublicKey);
    const result2 = await tx3.wait();
    const tx4 = await zeto.connect(deployer).register(Charlie.babyJubPublicKey);
    const result3 = await tx4.wait();

    circuit = await loadCircuit('anon_enc_nullifier_kyc');
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      'anon_enc_nullifier_kyc'
    ));

    const storage1 = new InMemoryDB(str2Bytes('alice'));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes('bob'));
    smtBob = new Merkletree(storage2, true, 64);

    const storage3 = new InMemoryDB(str2Bytes('kyc'));
    smtKyc = new Merkletree(storage3, true, 10);

    const publicKey1 = parseRegistryEvents(zeto, result1);
    await smtKyc.add(kycHash(publicKey1), kycHash(publicKey1));
    const publicKey2 = parseRegistryEvents(zeto, result2);
    await smtKyc.add(kycHash(publicKey2), kycHash(publicKey2));
    const publicKey3 = parseRegistryEvents(zeto, result3);
    await smtKyc.add(kycHash(publicKey3), kycHash(publicKey3));
  });

  it('onchain SMT root should be equal to the offchain SMT root', async function () {
    const root = await smtAlice.root();
    const onchainRoot = await zeto.getRoot();
    expect(onchainRoot).to.equal(0n);
    expect(root.string()).to.equal(onchainRoot.toString());
  });

  it('mint ERC20 tokens to Alice to deposit to Zeto should succeed', async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    const tx = await erc20.connect(deployer).mint(Alice.ethAddress, 100);
    await tx.wait();
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(100);

    const tx1 = await erc20.connect(Alice.signer).approve(zeto.target, 100);
    await tx1.wait();

    utxo100 = newUTXO(100, Alice);
    const { outputCommitments, encodedProof } = await prepareDepositProof(
      Alice,
      utxo100
    );
    const tx2 = await zeto
      .connect(Alice.signer)
      .deposit(100, outputCommitments[0], encodedProof);
    await tx2.wait();

    await smtAlice.add(utxo100.hash, utxo100.hash);
    await smtBob.add(utxo100.hash, utxo100.hash);
  });

  it('mint to Alice and transfer UTXOs honestly to Bob should succeed', async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // The authority mints a new UTXO and assigns it to Alice
    utxo1 = newUTXO(10, Alice);
    utxo2 = newUTXO(20, Alice);
    const result1 = await doMint(zeto, deployer, [utxo1, utxo2]);

    // check the private mint activity is not exposed in the ERC20 contract
    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    // hardhat doesn't have a good way to subscribe to events so we have to parse the Tx result object
    const mintEvents = parseUTXOEvents(zeto, result1);
    const [_utxo1, _utxo2] = mintEvents[0].outputs;
    await smtAlice.add(_utxo1, _utxo1);
    await smtAlice.add(_utxo2, _utxo2);
    let utxosRoot = await smtAlice.root();
    let onchainRoot = await zeto.getRoot();
    expect(utxosRoot.string()).to.equal(onchainRoot.toString());
    // Bob also locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtBob.add(_utxo1, _utxo1);
    await smtBob.add(_utxo2, _utxo2);

    // Alice proposes the output UTXOs for the transfer to Bob
    _utxo3 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo1, Alice);
    const nullifier2 = newNullifier(utxo2, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    const proof1 = await smtAlice.generateCircomVerifierProof(
      utxo1.hash,
      utxosRoot
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(
      utxo2.hash,
      utxosRoot
    );
    const utxoMerkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice generates inclusion proofs for the identities in the transaction
    const identitiesRoot = await smtKyc.root();
    const proof3 = await smtKyc.generateCircomVerifierProof(
      kycHash(Alice.babyJubPublicKey),
      identitiesRoot
    );
    const proof4 = await smtKyc.generateCircomVerifierProof(
      kycHash(Bob.babyJubPublicKey),
      identitiesRoot
    );
    const identityMerkleProofs = [
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
      proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
    ];

    // Alice transfers her UTXOs to Bob
    const result2 = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [nullifier1, nullifier2],
      [_utxo3, utxo4],
      utxosRoot.bigInt(),
      utxoMerkleProofs,
      identitiesRoot.bigInt(),
      identityMerkleProofs,
      [Bob, Alice]
    );

    // check the private transfer activity is not exposed in the ERC20 contract
    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtAlice.add(_utxo3.hash, _utxo3.hash);
    await smtAlice.add(utxo4.hash, utxo4.hash);
    utxosRoot = await smtAlice.root();
    onchainRoot = await zeto.getRoot();
    expect(utxosRoot.string()).to.equal(onchainRoot.toString());

    // Bob locally tracks the UTXOs inside the Sparse Merkle Tree
    // Bob parses the UTXOs from the onchain event
    const signerAddress = await Alice.signer.getAddress();
    const events = parseUTXOEvents(zeto, result2.txResult!);
    expect(events[0].submitter).to.equal(signerAddress);
    expect(events[0].inputs).to.deep.equal([nullifier1.hash, nullifier2.hash]);
    expect(events[0].outputs).to.deep.equal([_utxo3.hash, utxo4.hash]);
    await smtBob.add(events[0].outputs[0], events[0].outputs[0]);
    await smtBob.add(events[0].outputs[1], events[0].outputs[1]);

    // Bob uses the encrypted values in the event to decrypt and recover the UTXO value and salt
    const sharedKey = genEcdhSharedKey(
      Bob.babyJubPrivateKey,
      Alice.babyJubPublicKey
    );
    const plainText = poseidonDecrypt(
      events[0].encryptedValues,
      sharedKey,
      events[0].encryptionNonce,
      2
    );
    expect(plainText).to.deep.equal([25n, result2.plainTextSalt]);

    // Bob uses the decrypted values to construct the UTXO received from the transaction
    utxo3 = newUTXO(Number(plainText[0]), Bob, plainText[1]);
  }).timeout(600000);

  it('Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed', async function () {
    // Bob generates the nullifiers for the UTXO to be spent
    const nullifier1 = newNullifier(utxo3, Bob);

    // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
    const utxosRoot = await smtBob.root();
    const proof1 = await smtBob.generateCircomVerifierProof(
      utxo3.hash,
      utxosRoot
    );
    const proof2 = await smtBob.generateCircomVerifierProof(0n, utxosRoot);
    const utxosMerkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Bob proposes the output UTXOs
    utxo6 = newUTXO(10, Charlie);
    utxo7 = newUTXO(15, Bob);
    // Bob generates inclusion proofs for the identities in the transaction
    // using a shortcut with a shared SMT for all identities, but obviously
    // Bob would need his own SMT instance in a real-world scenario
    const identitiesRoot = await smtKyc.root();
    const proof3 = await smtKyc.generateCircomVerifierProof(
      kycHash(Bob.babyJubPublicKey),
      identitiesRoot
    );
    const proof4 = await smtKyc.generateCircomVerifierProof(
      kycHash(Charlie.babyJubPublicKey),
      identitiesRoot
    );
    const identitiesMerkleProofs = [
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
      proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Charlie)
      proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Bob)
    ];

    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    const result = await doTransfer(
      Bob,
      [utxo3, ZERO_UTXO],
      [nullifier1, ZERO_UTXO],
      [utxo6, utxo7],
      utxosRoot.bigInt(),
      utxosMerkleProofs,
      identitiesRoot.bigInt(),
      identitiesMerkleProofs,
      [Charlie, Bob]
    );

    // Bob keeps the local SMT in sync
    await smtBob.add(utxo6.hash, utxo6.hash);
    await smtBob.add(utxo7.hash, utxo7.hash);

    // Alice gets the new UTXOs from the onchain event and keeps the local SMT in sync
    const events = parseUTXOEvents(zeto, result.txResult!);
    await smtAlice.add(events[0].outputs[0], events[0].outputs[0]);
    await smtAlice.add(events[0].outputs[1], events[0].outputs[1]);
  }).timeout(600000);

  it('Alice withdraws her UTXOs to ERC20 tokens should succeed', async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo100, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    let root = await smtAlice.root();
    const proof1 = await smtAlice.generateCircomVerifierProof(
      utxo100.hash,
      root
    );
    const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice proposes the output ERC20 tokens
    withdrawChangeUTXO = newUTXO(20, Alice);

    const { nullifiers, outputCommitments, encodedProof } =
      await prepareNullifierWithdrawProof(
        Alice,
        [utxo100, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        withdrawChangeUTXO,
        root.bigInt(),
        merkleProofs
      );

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        80,
        nullifiers,
        outputCommitments[0],
        root.bigInt(),
        encodedProof
      );
    await tx.wait();

    // Alice tracks the UTXO inside the SMT
    await smtAlice.add(withdrawChangeUTXO.hash, withdrawChangeUTXO.hash);
    // Bob also locally tracks the UTXOs inside the SMT
    await smtBob.add(withdrawChangeUTXO.hash, withdrawChangeUTXO.hash);

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(80);
  });

  describe('unregistered user cases', function () {
    let storage3;
    let smtUnregistered: Merkletree;
    let unregisteredUtxo100: UTXO;

    before(() => {
      storage3 = new InMemoryDB(str2Bytes('unregistered'));
      smtUnregistered = new Merkletree(storage3, true, 64);
    });

    it('deposit by an unregistered user should succeed', async function () {
      const tx = await erc20
        .connect(deployer)
        .mint(unregistered.ethAddress, 100);
      await tx.wait();
      const tx1 = await erc20
        .connect(unregistered.signer)
        .approve(zeto.target, 100);
      await tx1.wait();

      unregisteredUtxo100 = newUTXO(100, unregistered);
      const { outputCommitments, encodedProof } = await prepareDepositProof(
        unregistered,
        unregisteredUtxo100
      );
      const tx2 = await zeto
        .connect(unregistered.signer)
        .deposit(100, outputCommitments[0], encodedProof);
      await tx2.wait();

      // Alice tracks the UTXO inside the SMT
      await smtAlice.add(unregisteredUtxo100.hash, unregisteredUtxo100.hash);
      // Bob also locally tracks the UTXOs inside the SMT
      await smtBob.add(unregisteredUtxo100.hash, unregisteredUtxo100.hash);
    });

    it('transfer from an unregistered user should fail', async function () {
      // catch up the local SMT for the unregistered user
      await smtUnregistered.add(utxo100.hash, utxo100.hash);
      await smtUnregistered.add(utxo1.hash, utxo1.hash);
      await smtUnregistered.add(utxo2.hash, utxo2.hash);
      await smtUnregistered.add(_utxo3.hash, _utxo3.hash);
      await smtUnregistered.add(utxo4.hash, utxo4.hash);
      await smtUnregistered.add(utxo6.hash, utxo6.hash);
      await smtUnregistered.add(utxo7.hash, utxo7.hash);
      await smtUnregistered.add(
        withdrawChangeUTXO.hash,
        withdrawChangeUTXO.hash
      );
      await smtUnregistered.add(
        unregisteredUtxo100.hash,
        unregisteredUtxo100.hash
      );
      const utxosRoot = await smtUnregistered.root();

      const nullifier = newNullifier(unregisteredUtxo100, unregistered);
      const output1 = newUTXO(100, Bob);
      const output2 = newUTXO(0, unregistered);
      const proof = await smtUnregistered.generateCircomVerifierProof(
        unregisteredUtxo100.hash,
        utxosRoot
      );
      const merkleProofs = [
        proof.siblings.map((s) => s.bigInt()),
        proof.siblings.map((s) => s.bigInt()),
      ];

      // add the unregistered user to the local KYC SMT, but not to the onchain SMT
      await smtKyc.add(
        kycHash(unregistered.babyJubPublicKey),
        kycHash(unregistered.babyJubPublicKey)
      );
      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(unregistered.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (unregistered)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (unregistered)
      ];
      await expect(
        doTransfer(
          unregistered,
          [unregisteredUtxo100, ZERO_UTXO],
          [nullifier, ZERO_UTXO],
          [output1, output2],
          utxosRoot.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
          [Bob, unregistered]
        )
      ).rejectedWith('Invalid proof');
    });

    it('the unregistered user can still withdraw their UTXOs to ERC20 tokens', async function () {
      const startingBalance = await erc20.balanceOf(unregistered.ethAddress);
      // unregistered user generates the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(unregisteredUtxo100, unregistered);

      // unregistered user generates inclusion proofs for the UTXOs to be spent
      let root = await smtUnregistered.root();
      const proof1 = await smtUnregistered.generateCircomVerifierProof(
        unregisteredUtxo100.hash,
        root
      );
      const proof2 = await smtUnregistered.generateCircomVerifierProof(
        0n,
        root
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // unregistered user proposes the output ERC20 tokens
      const unregisteredWithdrawChangeUTXO = newUTXO(0, unregistered);

      const { nullifiers, outputCommitments, encodedProof } =
        await prepareNullifierWithdrawProof(
          unregistered,
          [unregisteredUtxo100, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          unregisteredWithdrawChangeUTXO,
          root.bigInt(),
          merkleProofs
        );

      // unregistered user withdraws her UTXOs to ERC20 tokens
      const tx = await zeto
        .connect(unregistered.signer)
        .withdraw(
          100,
          nullifiers,
          outputCommitments[0],
          root.bigInt(),
          encodedProof
        );
      await tx.wait();

      // Alice tracks the UTXO inside the SMT
      await smtAlice.add(
        unregisteredWithdrawChangeUTXO.hash,
        unregisteredWithdrawChangeUTXO.hash
      );
      // Bob also locally tracks the UTXOs inside the SMT
      await smtBob.add(
        unregisteredWithdrawChangeUTXO.hash,
        unregisteredWithdrawChangeUTXO.hash
      );

      // unregistered user checks her ERC20 balance
      const endingBalance = await erc20.balanceOf(unregistered.ethAddress);
      expect(endingBalance - startingBalance).to.be.equal(100);
    });
  });

  describe('failure cases', function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== 'hardhat') {
      return;
    }

    it('Alice attempting to withdraw spent UTXOs should fail', async function () {
      // Alice generates the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(utxo100, Alice);

      // Alice generates inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo100.hash,
        root
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // Alice proposes the output ERC20 tokens
      withdrawChangeUTXO = newUTXO(90, Alice);

      const { nullifiers, outputCommitments, encodedProof } =
        await prepareNullifierWithdrawProof(
          Alice,
          [utxo100, ZERO_UTXO],
          [nullifier1, ZERO_UTXO],
          withdrawChangeUTXO,
          root.bigInt(),
          merkleProofs
        );

      // Alice withdraws her UTXOs to ERC20 tokens
      await expect(
        zeto
          .connect(Alice.signer)
          .withdraw(
            10,
            nullifiers,
            outputCommitments[0],
            root.bigInt(),
            encodedProof
          )
      ).rejectedWith('UTXOAlreadySpent');
    });

    it('mint existing unspent UTXOs should fail', async function () {
      await expect(doMint(zeto, deployer, [utxo4])).rejectedWith(
        'UTXOAlreadyOwned'
      );
    });

    it('mint existing spent UTXOs should fail', async function () {
      await expect(doMint(zeto, deployer, [utxo1])).rejectedWith(
        'UTXOAlreadyOwned'
      );
    });

    it('transfer spent UTXOs should fail (double spend protection)', async function () {
      // create outputs
      const _utxo1 = newUTXO(25, Bob);
      const _utxo2 = newUTXO(5, Alice);

      // generate the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(utxo1, Alice);
      const nullifier2 = newNullifier(utxo2, Alice);

      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        utxo1.hash,
        root
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        utxo2.hash,
        root
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
      ];

      await expect(
        doTransfer(
          Alice,
          [utxo1, utxo2],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
          [Bob, Alice]
        )
      ).rejectedWith('UTXOAlreadySpent');
    }).timeout(600000);

    it('transfer with existing UTXOs in the output should fail (mass conservation protection)', async function () {
      // give Bob another UTXO to be able to spend
      const _utxo1 = newUTXO(15, Bob);
      await doMint(zeto, deployer, [_utxo1]);
      await smtBob.add(_utxo1.hash, _utxo1.hash);

      const nullifier1 = newNullifier(utxo7, Bob);
      const nullifier2 = newNullifier(_utxo1, Bob);
      let root = await smtBob.root();
      const proof1 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const proof2 = await smtBob.generateCircomVerifierProof(
        _utxo1.hash,
        root
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Alice)
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, _utxo1],
          [nullifier1, nullifier2],
          [utxo1, utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
          [Alice, Alice]
        )
      ).rejectedWith('UTXOAlreadyOwned');
    }).timeout(600000);

    it('spend by using the same UTXO as both inputs should fail', async function () {
      const _utxo1 = newUTXO(20, Alice);
      const _utxo2 = newUTXO(10, Bob);
      const nullifier1 = newNullifier(utxo7, Bob);
      const nullifier2 = newNullifier(utxo7, Bob);
      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtBob.root();
      const proof1 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const proof2 = await smtBob.generateCircomVerifierProof(utxo7.hash, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Bob)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Alice)
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Bob)
      ];

      await expect(
        doTransfer(
          Bob,
          [utxo7, utxo7],
          [nullifier1, nullifier2],
          [_utxo1, _utxo2],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
          [Alice, Bob]
        )
      ).rejectedWith(`UTXODuplicate`);
    }).timeout(600000);

    it('transfer non-existing UTXOs should fail', async function () {
      const nonExisting1 = newUTXO(25, Alice);
      const nonExisting2 = newUTXO(20, Alice, nonExisting1.salt);

      // add to our local SMT (but they don't exist on the chain)
      await smtAlice.add(nonExisting1.hash, nonExisting1.hash);
      await smtAlice.add(nonExisting2.hash, nonExisting2.hash);

      // generate the nullifiers for the UTXOs to be spent
      const nullifier1 = newNullifier(nonExisting1, Alice);
      const nullifier2 = newNullifier(nonExisting2, Alice);

      // generate inclusion proofs for the UTXOs to be spent
      let root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        nonExisting1.hash,
        root
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(
        nonExisting2.hash,
        root
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];

      // propose the output UTXOs
      const _utxo1 = newUTXO(30, Charlie);
      const utxo7 = newUTXO(15, Bob);

      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const proof5 = await smtKyc.generateCircomVerifierProof(
        kycHash(Charlie.babyJubPublicKey),
        identitiesRoot
      );
      const identitiesMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
        proof4.siblings.map((s) => s.bigInt()), // identity proof for the 1st owner of the output UTXO (Bob)
        proof5.siblings.map((s) => s.bigInt()), // identity proof for the 2nd owner of the output UTXO (Charlie)
      ];

      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nullifier1, nullifier2],
          [utxo7, _utxo1],
          root.bigInt(),
          merkleProofs,
          identitiesRoot.bigInt(),
          identitiesMerkleProofs,
          [Bob, Charlie]
        )
      ).rejectedWith('UTXORootNotFound');
    }).timeout(600000);
  });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    utxosRoot: BigInt,
    utxosMerkleProof: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[]
  ) {
    let nullifiers: [BigNumberish, BigNumberish];
    let outputCommitments: [BigNumberish, BigNumberish];
    let encryptedValues: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let encodedProof: any;
    const result = await prepareProof(
      signer,
      inputs,
      _nullifiers,
      outputs,
      utxosRoot,
      utxosMerkleProof,
      identitiesRoot,
      identitiesMerkleProof,
      owners
    );

    nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish
    ];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptedValues = result.encryptedValues;
    encryptionNonce = result.encryptionNonce;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      utxosRoot,
      encryptedValues,
      encryptionNonce,
      encodedProof
    );
    // add the clear text value so that it can be used by tests to compare with the decrypted value
    return { txResult, plainTextSalt: outputs[0].salt };
  }

  async function prepareProof(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    utxosRoot: BigInt,
    utxosMerkleProof: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[]
  ) {
    const nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish
    ];
    const inputCommitments: [BigNumberish, BigNumberish] = inputs.map(
      (input) => input.hash
    ) as [BigNumberish, BigNumberish];
    const inputValues = inputs.map((input) => BigInt(input.value || 0n));
    const inputSalts = inputs.map((input) => input.salt || 0n);
    const outputCommitments: [BigNumberish, BigNumberish] = outputs.map(
      (output) => output.hash
    ) as [BigNumberish, BigNumberish];
    const outputValues = outputs.map((output) => BigInt(output.value || 0n));
    const outputOwnerPublicKeys: [
      [BigNumberish, BigNumberish],
      [BigNumberish, BigNumberish]
    ] = owners.map((owner) => owner.babyJubPublicKey) as [
      [BigNumberish, BigNumberish],
      [BigNumberish, BigNumberish]
    ];
    const encryptionNonce: BigNumberish = newEncryptionNonce() as BigNumberish;
    const encryptInputs = stringifyBigInts({
      encryptionNonce,
    });

    const startWitnessCalculation = Date.now();
    const inputObj = {
      nullifiers,
      inputCommitments,
      inputValues,
      inputSalts,
      inputOwnerPrivateKey: signer.formattedPrivateKey,
      utxosRoot,
      enabled: [nullifiers[0] !== 0n ? 1 : 0, nullifiers[1] !== 0n ? 1 : 0],
      utxosMerkleProof,
      identitiesRoot,
      identitiesMerkleProof,
      outputCommitments,
      outputValues,
      outputSalts: outputs.map((output) => output.salt || 0n),
      outputOwnerPublicKeys,
      ...encryptInputs,
    };
    const witness = await circuit.calculateWTNSBin(inputObj, true);
    const timeWithnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof, publicSignals } = (await groth16.prove(
      provingKey,
      witness
    )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
    const timeProofGeneration = Date.now() - startProofGeneration;

    console.log(
      `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`
    );

    const encodedProof = encodeProof(proof);
    const encryptedValues = publicSignals.slice(0, 4);
    return {
      inputCommitments,
      outputCommitments,
      encryptedValues,
      encryptionNonce,
      encodedProof,
    };
  }

  async function sendTx(
    signer: User,
    nullifiers: [BigNumberish, BigNumberish],
    outputCommitments: [BigNumberish, BigNumberish],
    root: BigNumberish,
    encryptedValues: BigNumberish[],
    encryptionNonce: BigNumberish,
    encodedProof: any
  ) {
    const startTx = Date.now();
    const tx = await zeto
      .connect(signer.signer)
      .transfer(
        nullifiers,
        outputCommitments,
        root,
        encryptionNonce,
        encryptedValues,
        encodedProof
      );
    const results: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${
        results?.gasUsed
      }`
    );
    return results;
  }
});
