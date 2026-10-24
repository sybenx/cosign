/* tslint:disable */
/* eslint-disable */

/**
 * `partials_json`: `[[idx, z], …]`.
 */
export function aggregate(group_json: string, msg: string, commits_json: string, partials_json: string): string;

/**
 * Returns `{"nonces": hex, "commit": {"idx", "D", "E"}}`.
 */
export function commit(group_json: string, idx: number, secret: string): string;

/**
 * A key you already have, dealt at `idxs`: `{"groupX", "shares": [{idx, secret, sharePub}]}`.
 */
export function dealFromSecret(secret: Uint8Array, idxs: Uint16Array, threshold: number): string;

/**
 * DKG part 1 for one share: `{"secret", "package"}`.
 */
export function dkgPart1(idx: number, max_signers: number, min_signers: number): string;

/**
 * DKG part 2: `others` is `[[idx, package], …]`. Returns `{"secret", "packages": [[toIdx, package], …]}`.
 */
export function dkgPart2(secret: string, others_json: string): string;

/**
 * DKG part 3: returns `{"share", "groupX", "members": [{idx, sharePub}, …]}`.
 */
export function dkgPart3(idx: number, secret2: string, others_round1_json: string, round2_json: string): string;

export function ecdhCombine(parts: string[]): string;

export function ecdhPartial(idx: number, secret: string, participants: Uint16Array, peer_x: string): string;

/**
 * The key from `threshold` of its shares (`[[idx, secret], …]`), as 32 bytes.
 */
export function reconstruct(group_json: string, shares_json: string): Uint8Array;

/**
 * Returns `[[helperIdx, delta], …]`.
 */
export function repairStep1(group_json: string, idx: number, secret: string, helpers: Uint16Array, participant: number): string;

export function repairStep2(deltas: string[]): string;

export function repairStep3(group_json: string, sigmas: string[], participant: number): string;

export function sharePub(secret: string): string;

export function sharePubAt(group_json: string, k: number): string;

export function sign(group_json: string, idx: number, secret: string, nonces: string, msg: string, commits_json: string): string;

export function verifyPartial(group_json: string, msg: string, commits_json: string, idx: number, z: string): boolean;
