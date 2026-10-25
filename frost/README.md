# cosign-frost

Cosign's signing math on the Zcash Foundation's FROST (`frost-secp256k1-tr` 2.2:
RFC 9591, secp256k1, BIP-340 signatures). One small API, built two ways:

Every build sets `RUSTFLAGS` so the machine that built it stays out of the binary:
without it, each crate path from the build host (`~/.cargo/registry/…`) is baked into
the `.so` and the `.wasm`, and ships in the app and this repository.

```sh
export RUSTFLAGS="--remap-path-prefix=$HOME=/build --remap-path-prefix=$PWD=/src"
```

- **Server (WebAssembly):** `cargo build --release --target wasm32-unknown-unknown --features wasm`,
  then `wasm-bindgen --target nodejs --out-dir ../server/frost-wasm --out-name cosign_frost target/wasm32-unknown-unknown/release/cosign_frost.wasm`.
- **Phone (JNI):** `cargo ndk -t arm64-v8a -t x86_64 -o ../android/cosign/src/main/jniLibs build --release --features android`.
  For the phone's unit tests on a computer: `cargo build --release --features android`.

`cargo test` checks that shares from Cosign's earlier hand-rolled dealer sign with the
library, verify as plain BIP-340, and that threshold ECDH matches the earlier math.

The frost-core signing, DKG and repair code was audited by NCC Group; its refresh
functions came later and haven't been.
