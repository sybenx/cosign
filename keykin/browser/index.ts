// keykin/device for the browser (the extension's member, Doors §3.1): the device, the relay transport over the
// browser's WebSocket, the invite and join codes, the paper's words and the FROST loader. The extension builds
// keykin/frost with `--target web` (../frost-wasm-web), initialises it and hands it to `useWasm` before any signing.
// Nothing here imports a Node module; storage is the extension's own (`DeviceNode.attach({ save })`, `restore`).
export { DeviceNode } from '../device/node.ts';
export { RelayNet } from '../runtime/relay.ts';
export { useWasm } from '../src/wasm.ts';
export { Inviter, Joiner, parseCode } from '../src/join.ts';
// Joining (core §4.1): with another device's invite code, or by showing this device's own hello code as a QR.
export { joinByCode, joinByShowing } from '../device/join.ts';
// A site's requests through any door (Doors §1–§2): `dev.doors.request(entryId, method, params, { origin })` (the asking page's origin, as the browser reports it); the paper check is
// `dev.checkPaper(words)`.
export { DoorRequests, type DoorCaller, type DoorAnswer } from '../device/doors-request.ts';
export { backupWords, readBackupWords } from '../src/backup.ts';
export { newKey } from '../src/event.ts';
