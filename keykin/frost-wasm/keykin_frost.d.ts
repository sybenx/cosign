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
