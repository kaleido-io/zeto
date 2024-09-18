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
pragma solidity ^0.8.20;

import {Groth16Verifier_CheckHashesValue} from "./lib/verifier_check_hashes_value.sol";
import {Groth16Verifier_CheckNullifierValue} from "./lib/verifier_check_nullifier_value.sol";
import {Groth16Verifier_AnonEncNullifierKyc} from "./lib/verifier_anon_enc_nullifier_kyc.sol";
import {ZetoNullifier} from "./lib/zeto_nullifier.sol";
import {ZetoFungibleWithdrawWithNullifiers} from "./lib/zeto_fungible_withdraw_nullifier.sol";
import {Registry} from "./lib/registry.sol";
import {Commonlib} from "./lib/common.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "hardhat/console.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity, encryption and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the encrypted value in the input is derived from the receiver's UTXO value and encrypted with a shared secret using the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonEncNullifierKyc is
    ZetoNullifier,
    ZetoFungibleWithdrawWithNullifiers,
    Registry,
    UUPSUpgradeable
{
    Groth16Verifier_AnonEncNullifierKyc verifier;

    function initialize(
        address initialOwner,
        Groth16Verifier_AnonEncNullifierKyc _verifier,
        Groth16Verifier_CheckHashesValue _depositVerifier,
        Groth16Verifier_CheckNullifierValue _withdrawVerifier
    ) public initializer {
        __Registry_init();
        __ZetoNullifier_init(initialOwner);
        __ZetoFungibleWithdrawWithNullifiers_init(
            _depositVerifier,
            _withdrawVerifier
        );
        verifier = _verifier;
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function register(uint256[2] memory publicKey) public onlyOwner {
        _register(publicKey);
    }
    /**
     * @dev the main function of the contract, which transfers values from one account (represented by Babyjubjub public keys)
     *      to one or more receiver accounts (also represented by Babyjubjub public keys). One of the two nullifiers may be zero
     *      if the transaction only needs one UTXO to be spent. Equally one of the two outputs may be zero if the transaction
     *      only needs to create one new UTXO.
     *
     * @param nullifiers Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param root The root hash of the Sparse Merkle Tree that contains the nullifiers.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransferWithEncryptedValues} event.
     */
    function transfer(
        uint256[2] memory nullifiers,
        uint256[2] memory outputs,
        uint256 root,
        uint256 encryptionNonce,
        uint256[4] memory encryptedValues,
        Commonlib.Proof calldata proof
    ) public returns (bool) {
        require(
            validateTransactionProposal(nullifiers, outputs, root),
            "Invalid transaction proposal"
        );

        // construct the public inputs
        uint256[13] memory publicInputs;
        publicInputs[0] = encryptedValues[0]; // encrypted value for the receiver UTXO
        publicInputs[1] = encryptedValues[1]; // encrypted salt for the receiver UTXO
        publicInputs[2] = encryptedValues[2]; // parity bit for the cipher text
        publicInputs[3] = encryptedValues[3]; // parity bit for the cipher text
        publicInputs[4] = nullifiers[0];
        publicInputs[5] = nullifiers[1];
        publicInputs[6] = root;
        publicInputs[7] = (nullifiers[0] == 0) ? 0 : 1; // if the first nullifier is empty, disable its MT proof verification
        publicInputs[8] = (nullifiers[1] == 0) ? 0 : 1; // if the second nullifier is empty, disable its MT proof verification
        publicInputs[9] = getIdentitiesRoot();
        publicInputs[10] = outputs[0];
        publicInputs[11] = outputs[1];
        publicInputs[12] = encryptionNonce;

        // // Check the proof
        require(
            verifier.verifyProof(proof.pA, proof.pB, proof.pC, publicInputs),
            "Invalid proof"
        );

        // accept the transaction to consume the input UTXOs and produce new UTXOs
        processInputsAndOutputs(nullifiers, outputs);

        uint256[] memory nullifierArray = new uint256[](nullifiers.length);
        uint256[] memory outputArray = new uint256[](outputs.length);
        uint256[] memory encryptedValuesArray = new uint256[](
            encryptedValues.length
        );
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            nullifierArray[i] = nullifiers[i];
            outputArray[i] = outputs[i];
        }
        for (uint256 i = 0; i < encryptedValues.length; ++i) {
            encryptedValuesArray[i] = encryptedValues[i];
        }

        emit UTXOTransferWithEncryptedValues(
            nullifierArray,
            outputArray,
            encryptionNonce,
            encryptedValuesArray,
            msg.sender
        );
        return true;
    }

    // in the current design, no KYC check is performed for deposit & withdraw functions
    // this is to reduce gas fee for deposit and withdraw function
    // users that doesn't pass KYC check will not be able to participate in transfers
    // because the transfer circuit requires the input and output owners to be in the KYC list
    // Therefore, token circulation from & to parties that are not in the KYC list is prevented
    function deposit(
        uint256 amount,
        uint256 utxo,
        Commonlib.Proof calldata proof
    ) public {
        _deposit(amount, utxo, proof);
        uint256[] memory utxos = new uint256[](1);
        utxos[0] = utxo;
        _mint(utxos);
    }

    function withdraw(
        uint256 amount,
        uint256[2] memory nullifiers,
        uint256 output,
        uint256 root,
        Commonlib.Proof calldata proof
    ) public {
        validateTransactionProposal(nullifiers, [output, 0], root);
        _withdrawWithNullifiers(amount, nullifiers, output, root, proof);
        processInputsAndOutputs(nullifiers, [output, 0]);
    }

    function mint(uint256[] memory utxos) public onlyOwner {
        _mint(utxos);
    }
}
