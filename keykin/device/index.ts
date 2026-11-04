// keykin/device: what an app or extension builds a Keykin member from. Pure TypeScript with no `node:`
// imports (test/device.test.ts walks the graph), so it bundles for a browser; FROST comes from the web
// build of keykin/frost, handed to `useWasm` first.
//
//   const d = new DeviceNode(transport, 'Chrome on Mac', null);   // an extension is lockless (core §6.1)
//   d.attach(store);                                             // its state goes to the app's store
//   DeviceNode.restore(transport, store.load(key), { lock })     // and comes back, checked (§4.4)

export { DeviceNode, PaperHolder, FriendNode, approvalListOf } from './node.ts';
export { DataKeys, type DataKey } from './datakey.ts';
export { Members, type RemovedEntry, type DeviceKey, type MembersEvent } from './members.ts';
export { memberSign, memberVerify, memberDigest, registerDomain, registeredDomains, domainFault } from './membersig.ts';
export { RelayNet, type RelayNetOpts } from '../runtime/relay.ts';
export type { Transport, Node } from '../runtime/net.ts';
export { useWasm } from '../src/wasm.ts';
export { softLock, checkAssertion, type Lock, type LockPub, type Assertion } from '../src/lock.ts';
export { approveLock, approvePair, approvePaper, approvePaperRequest, approveRecovery } from '../src/approval.ts';
export { parseCode } from '../src/join.ts';
export { msg } from '../src/msg.ts';
export { KeykinError } from '../src/bytes.ts';
export { newKey, verifyEvent, siteEvent, type NostrEvent, type Unsigned, type KeyPair } from '../src/event.ts';
export type { Change, Approval, EpochContent, MemberEntry } from '../src/types.ts';
