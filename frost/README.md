# cosign-frost

Cosign's signing math on the Zcash Foundation's FROST (`frost-secp256k1-tr` 2.2:
RFC 9591, secp256k1, BIP-340 signatures). One small API, built two ways:

- **Server (WebAssembly):** `cargo build --release --target wasm32-unknown-unknown --features wasm`,
  then `wasm-bindgen --target nodejs --out-dir ../server/frost-wasm --out-name cosign_frost target/wasm32-unknown-unknown/release/cosign_frost.wasm`.
- **Phone (JNI):** `cargo ndk -t arm64-v8a -t x86_64 -o ../android/app/src/main/jniLibs build --release --features android`.
  For the phone's unit tests on a computer: `cargo build --release --features android`.

`cargo test` checks that shares from Cosign's earlier hand-rolled dealer sign with the
library, verify as plain BIP-340, and that threshold ECDH matches the earlier math.

The frost-core signing, DKG and repair code was audited by NCC Group; its refresh
functions came later and haven't been.
