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
import {IGroth16Verifier} from "./lib/interfaces/izeto_verifier.sol";
import {ZetoFungibleWithdraw} from "./lib/zeto_fungible_withdraw.sol";
import {ZetoBase} from "./lib/zeto_base.sol";
import {Commonlib} from "./lib/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity, and encryption
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the input values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
///        - the encrypted value in the input is derived from the receiver's UTXO value and encrypted with a shared secret using
///          the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
contract Zeto_AnonEnc is
    IZeto,
    ZetoBase,
    ZetoFungibleWithdraw,
    UUPSUpgradeable
{
    function initialize(
        string memory name,
        string memory symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public initializer {
        __ZetoBase_init(name, symbol, initialOwner, verifiers);
        __ZetoFungibleWithdraw_init(
            (IGroth16Verifier)(verifiers.depositVerifier),
            (IGroth16Verifier)(verifiers.withdrawVerifier),
            (IGroth16Verifier)(verifiers.batchWithdrawVerifier)
        );
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256 encryptionNonce,
        uint256[2] memory ecdhPublicKey,
        uint256[] memory encryptedValues
    ) internal pure returns (uint256[] memory publicInputs) {
        uint256 size = ecdhPublicKey.length +
            encryptedValues.length +
            inputs.length +
            outputs.length +
            1; // encryptionNonce
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
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }

        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }

        // copy encryption nonce
        publicInputs[piIndex++] = encryptionNonce;

        return publicInputs;
    }

    /**
     * @dev the main function of the contract.
     *
     * @param inputs Array of UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransferWithEncryptedValues} event.
     */
    function transfer(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256 encryptionNonce,
        uint256[2] memory ecdhPublicKey,
        uint256[] memory encryptedValues,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public returns (bool) {
        // Check and pad commitments
        inputs = checkAndPadCommitments(inputs);
        outputs = checkAndPadCommitments(outputs);
        uint256[] memory lockedOutputs;
        validateTransactionProposal(inputs, outputs, lockedOutputs, false);

        // Check the proof
        uint256[] memory publicInputs = constructPublicInputs(
            inputs,
            outputs,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValues
        );
        bool isBatch = (inputs.length > 2 || outputs.length > 2);
        verifyProof(proof, publicInputs, isBatch, false);

        // accept the transaction proposal and process the inputs and outputs
        processInputsAndOutputs(inputs, outputs, lockedOutputs, false);

        uint256[] memory encryptedValuesArray = new uint256[](
            encryptedValues.length
        );
        for (uint256 i = 0; i < encryptedValues.length; ++i) {
            encryptedValuesArray[i] = encryptedValues[i];
        }

        emit UTXOTransferWithEncryptedValues(
            inputs,
            outputs,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValuesArray,
            msg.sender,
            data
        );
        return true;
    }

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
        uint256[] memory inputs,
        uint256 output,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory outputs = new uint256[](inputs.length);
        outputs[0] = output;
        // Check and pad commitments
        inputs = checkAndPadCommitments(inputs);
        outputs = checkAndPadCommitments(outputs);
        uint256[] memory lockedOutputs;
        validateTransactionProposal(inputs, outputs, lockedOutputs, false);

        _withdraw(amount, inputs, output, proof);

        processInputsAndOutputs(inputs, outputs, lockedOutputs, false);
        emit UTXOWithdraw(amount, inputs, output, msg.sender, data);
    }

    function mint(
        uint256[] memory utxos,
        bytes calldata data
    ) public onlyOwner {
        _mint(utxos, data);
    }
}
