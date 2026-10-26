// The signing member of a Cosign key, as a library: what a device does, with the parts of
// the key kept by whatever is hosting it (ops.ts). The browser extension, the Marble Mac app
// and an iOS app all want the same half, and this is it.

export { openDevice, Device } from './device.ts';
export type { Account, Host, Member } from './device.ts';
export type { ShareOps, DeviceState, Group, Commit } from './ops.ts';
export { Mailbox, pubOf, KIND_MEMBER } from './mailbox.ts';
