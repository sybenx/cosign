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

export function ecdhCombine(parts: string[]): string;

export function ecdhPartial(idx: number, secret: string, participants: Uint16Array, peer_x: string): string;

export function sharePub(secret: string): string;

export function sign(group_json: string, idx: number, secret: string, nonces: string, msg: string, commits_json: string): string;

export function verifyPartial(group_json: string, msg: string, commits_json: string, idx: number, z: string): boolean;
