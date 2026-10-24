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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly aggregate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly commit: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly dealFromSecret: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly dkgPart1: (a: number, b: number, c: number) => [number, number, number, number];
    readonly dkgPart2: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly dkgPart3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly ecdhCombine: (a: number, b: number) => [number, number, number, number];
    readonly ecdhPartial: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
    readonly reconstruct: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly repairStep1: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly repairStep2: (a: number, b: number) => [number, number, number, number];
    readonly repairStep3: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
    readonly sharePub: (a: number, b: number) => [number, number, number, number];
    readonly sharePubAt: (a: number, b: number, c: number) => [number, number, number, number];
    readonly sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number, number, number];
    readonly verifyPartial: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
