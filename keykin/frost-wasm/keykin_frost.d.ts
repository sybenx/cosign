/* tslint:disable */
/* eslint-disable */

/**
 * Aggregate `[[i, z], …]` into a BIP-340 signature (64 bytes hex). Fails unless it verifies.
 */
export function aggregate(commitment_json: string, msg: string, commits_json: string, partials_json: string): string;

/**
 * Round 1 for one index: `{"nonces": hex(hiding ‖ binding), "commit": {i, D, E}}`. `hedge` is the
 * 32-byte random input of §5.2. The nonces never leave process memory.
 */
export function commit(commitment_json: string, i: string, share: string, hedge: string): string;

/**
 * Part 1 for one index: `{"secret", "package"}`. `hedge` seeds the polynomial and proof (§5.2's stream).
 */
export function dkgPart1(i: string, max_signers: number, min_signers: number, hedge: string): string;

/**
 * Part 2: from every other index's round-1 package (`[[i, package], …]`), a round-2 package for each.
 */
export function dkgPart2(secret: string, others_json: string): string;

/**
 * Part 3: `{"share", "groupX", "points": [[i, P_i], …]}`, even y.
 */
export function dkgPart3(secret2: string, round1_json: string, round2_json: string): string;

/**
 * Repair step 1 (§4.2 step 3) for one helper index: `[[helper i, delta], …]`, one per helper.
 */
export function repairStep1(commitment_json: string, helpers_json: string, i: string, share: string, participant: string): string;

/**
 * Repair step 2: a sigma from the deltas meant for one helper index (or several, summed).
 */
export function repairStep2(deltas_json: string): string;

/**
 * Repair step 3, by the new holder: its share from the sigmas, checked against `P_i^S`.
 */
export function repairStep3(commitment_json: string, sigmas_json: string, participant: string): string;

/**
 * The share point `P_i^S` for identifier `i`, compressed hex.
 */
export function sharePoint(commitment_json: string, i: string): string;

/**
 * Round 2 for one index: its `z` for `msg` (the 32-byte event id) over every commitment.
 */
export function sign(commitment_json: string, i: string, share: string, nonces: string, msg: string, commits_json: string): string;

/**
 * Check one index's `z` against `P_i^S` (`verify_signature_share`).
 */
export function verifyPartial(commitment_json: string, msg: string, commits_json: string, i: string, z: string): boolean;
