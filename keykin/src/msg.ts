// A Core message body (§9.1): version, type, group, epoch, a fresh 16-byte id and its lifetime class.

import { bytesToHex, randomBytes } from './bytes.ts';

export const rid = () => bytesToHex(randomBytes(16));
export const msg = (type: string, g: string, epoch: string, cls: string, extra: object = {}) => ({ v: 1, type, g, epoch, id: rid(), cls, ...extra });
