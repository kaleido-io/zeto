// Copyright © 2025 Kaleido, Inc.
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

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import {
  DepositVerifierModule,
  WithdrawVerifierModule,
  BatchWithdrawVerifierModule,
} from "./lib/deps";

const VerifierModule = buildModule("Groth16Verifier_Anon", (m) => {
  const verifier = m.contract("Groth16Verifier_Anon", []);
  return { verifier };
});

const BatchVerifierModule = buildModule("Groth16Verifier_AnonBatch", (m) => {
  const verifier = m.contract("Groth16Verifier_AnonBatch", []);
  return { verifier };
});

const BurnVerifierModule = buildModule("Groth16Verifier_Burn", (m) => {
  const verifier = m.contract("Groth16Verifier_Burn", []);
  return { verifier };
});

const BatchBurnVerifierModule = buildModule(
  "Groth16Verifier_BurnBatch",
  (m) => {
    const verifier = m.contract("Groth16Verifier_BurnBatch", []);
    return { verifier };
  },
);

export default buildModule("Zeto_AnonBurnable", (m) => {
  const { verifier } = m.useModule(VerifierModule);
  const { verifier: batchVerifier } = m.useModule(BatchVerifierModule);
  const { verifier: depositVerifier } = m.useModule(DepositVerifierModule);
  const { verifier: withdrawVerifier } = m.useModule(WithdrawVerifierModule);
  const { verifier: batchWithdrawVerifier } = m.useModule(
    BatchWithdrawVerifierModule,
  );
  const { verifier: burnVerifier } = m.useModule(BurnVerifierModule);
  const { verifier: batchBurnVerifier } = m.useModule(BatchBurnVerifierModule);
  return {
    depositVerifier,
    withdrawVerifier,
    burnVerifier,
    verifier,
    batchVerifier,
    batchWithdrawVerifier,
    batchBurnVerifier,
  };
});
