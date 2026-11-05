/* tslint:disable */
/* eslint-disable */

export function aggregate(c: string, msg: string, commits: string, partials: string): string;

export function commit(c: string, i: string, share: string, hedge: string): string;

export function dkgPart1(i: string, max: number, min: number, hedge: string): string;

export function dkgPart2(secret: string, others: string): string;

export function dkgPart3(secret2: string, r1: string, r2: string): string;

export function repairStep1(c: string, helpers: string, i: string, share: string, participant: string): string;

export function repairStep2(deltas: string): string;

export function repairStep3(c: string, sigmas: string, participant: string): string;

export function sharePoint(c: string, i: string): string;

export function sign(c: string, i: string, share: string, nonces: string, msg: string, commits: string): string;

export function verifyPartial(c: string, msg: string, commits: string, i: string, z: string): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly aggregate: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly commit: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly dkgPart1: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly dkgPart2: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly dkgPart3: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly repairStep1: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
    readonly repairStep2: (a: number, b: number) => [number, number, number, number];
    readonly repairStep3: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly sharePoint: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => [number, number, number, number];
    readonly verifyPartial: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
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
