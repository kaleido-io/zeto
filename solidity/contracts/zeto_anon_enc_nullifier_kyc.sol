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
pragma solidity ^0.8.27;

import {IZeto} from "./lib/interfaces/izeto.sol";
import {Groth16Verifier_Deposit} from "./verifiers/verifier_deposit.sol";
import {Groth16Verifier_WithdrawNullifier} from "./verifiers/verifier_withdraw_nullifier.sol";
import {Groth16Verifier_WithdrawNullifierBatch} from "./verifiers/verifier_withdraw_nullifier_batch.sol";
import {Groth16Verifier_AnonEncNullifierKyc} from "./verifiers/verifier_anon_enc_nullifier_kyc.sol";
import {Groth16Verifier_AnonEncNullifierKycBatch} from "./verifiers/verifier_anon_enc_nullifier_kyc_batch.sol";
import {ZetoNullifier} from "./lib/zeto_nullifier.sol";
import {ZetoFungibleWithdrawWithNullifiers} from "./lib/zeto_fungible_withdraw_nullifier.sol";
import {Registry} from "./lib/registry.sol";
import {Commonlib} from "./lib/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

uint256 constant INPUT_SIZE = 19;
uint256 constant BATCH_INPUT_SIZE = 75;

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
    IZeto,
    IZetoInitializable,
    ZetoNullifier,
    ZetoFungibleWithdrawWithNullifiers,
    Registry,
    UUPSUpgradeable
{
    Groth16Verifier_AnonEncNullifierKyc internal _verifier;
    Groth16Verifier_AnonEncNullifierKycBatch internal _batchVerifier;

    function initialize(
        string memory name,
        string memory symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public initializer {
        __Registry_init();
        __ZetoNullifier_init(name, symbol, initialOwner);
        __ZetoFungibleWithdrawWithNullifiers_init(
            (Groth16Verifier_Deposit)(verifiers.depositVerifier),
            (Groth16Verifier_WithdrawNullifier)(verifiers.withdrawVerifier),
            (Groth16Verifier_WithdrawNullifierBatch)(
                verifiers.batchWithdrawVerifier
            )
        );
        _verifier = (Groth16Verifier_AnonEncNullifierKyc)(verifiers.verifier);
        _batchVerifier = (Groth16Verifier_AnonEncNullifierKycBatch)(
            verifiers.batchVerifier
        );
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function constructPublicInputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        uint256 encryptionNonce,
        uint256[2] memory ecdhPublicKey,
        uint256[] memory encryptedValues,
        uint256 size
    ) internal view returns (uint256[] memory publicInputs) {
        publicInputs = new uint256[](size);
        uint256 piIndex = 0;
        // copy the ecdh public key
        for (uint256 i = 0; i < ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = ecdhPublicKey[i];
        }
        // copy the encrypted value, salt and parity bit
        for (uint256 i = 0; i < encryptedValues.length; ++i) {
            publicInputs[piIndex++] = encryptedValues[i];
        }
        // copy input commitments
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }

        // copy root
        publicInputs[piIndex++] = root;

        // populate enables
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }

        // copy identities root
        publicInputs[piIndex++] = getIdentitiesRoot();
        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }

        // copy encryption nonce
        publicInputs[piIndex++] = encryptionNonce;

        return publicInputs;
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
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        uint256 encryptionNonce,
        uint256[2] memory ecdhPublicKey,
        uint256[] memory encryptedValues,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public returns (bool) {
        // Check and pad commitments
        nullifiers = checkAndPadCommitments(nullifiers);
        outputs = checkAndPadCommitments(outputs);
        validateTransactionProposal(nullifiers, outputs, root, false);

        // Check the proof
        if (nullifiers.length > 2 || outputs.length > 2) {
            uint256[] memory publicInputs = constructPublicInputs(
                nullifiers,
                outputs,
                root,
                encryptionNonce,
                ecdhPublicKey,
                encryptedValues,
                BATCH_INPUT_SIZE
            );
            // construct the public inputs for batchVerifier
            uint256[BATCH_INPUT_SIZE] memory fixedSizeInputs;
            for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
                fixedSizeInputs[i] = publicInputs[i];
            }

            // Check the proof using batchVerifier
            require(
                _batchVerifier.verifyProof(
                    proof.pA,
                    proof.pB,
                    proof.pC,
                    fixedSizeInputs
                ),
                "Invalid proof (batch)"
            );
        } else {
            uint256[] memory publicInputs = constructPublicInputs(
                nullifiers,
                outputs,
                root,
                encryptionNonce,
                ecdhPublicKey,
                encryptedValues,
                INPUT_SIZE
            );
            // construct the public inputs for verifier
            uint256[INPUT_SIZE] memory fixedSizeInputs;
            for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
                fixedSizeInputs[i] = publicInputs[i];
            }
            // Check the proof
            require(
                _verifier.verifyProof(
                    proof.pA,
                    proof.pB,
                    proof.pC,
                    fixedSizeInputs
                ),
                "Invalid proof"
            );
        }

        // accept the transaction to consume the input UTXOs and produce new UTXOs
        uint256[] memory empty;
        processInputsAndOutputs(nullifiers, outputs, empty, address(0));

        uint256[] memory encryptedValuesArray = new uint256[](
            encryptedValues.length
        );
        for (uint256 i = 0; i < encryptedValues.length; ++i) {
            encryptedValuesArray[i] = encryptedValues[i];
        }

        emit UTXOTransferWithEncryptedValues(
            nullifiers,
            outputs,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValuesArray,
            msg.sender,
            data
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
        uint256[] memory outputs,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public {
        _deposit(amount, outputs, proof);
        _mint(outputs, data);
    }

    function withdraw(
        uint256 amount,
        uint256[] memory nullifiers,
        uint256 output,
        uint256 root,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory outputs = new uint256[](nullifiers.length);
        outputs[0] = output;
        // Check and pad commitments
        nullifiers = checkAndPadCommitments(nullifiers);
        outputs = checkAndPadCommitments(outputs);
        validateTransactionProposal(nullifiers, outputs, root, false);

        _withdrawWithNullifiers(amount, nullifiers, output, root, proof);
        uint256[] memory empty;
        processInputsAndOutputs(nullifiers, outputs, empty, address(0));
        emit UTXOWithdraw(amount, nullifiers, output, msg.sender, data);
    }

    function mint(
        uint256[] memory utxos,
        bytes calldata data
    ) public onlyOwner {
        _mint(utxos, data);
    }
}
