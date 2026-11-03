//! Keykin Core's FROST calls (core.md §1, §4.2, §5.1–5.2), on the Zcash Foundation's
//! `frost-secp256k1-tr` 2.2. Unlike Cosign 0.12's `frost/` wrapper, every index is a FROST
//! identifier given as a 32-byte big-endian scalar (§3.2), the group is named by its current
//! commitment `C_S` (§6.7.1) so every share point is derived, and nonces take a caller-supplied
//! hedge (§5.2) instead of drawing OS randomness themselves.
//!
//! The API speaks hex and JSON. Commitment: `["<C0>", "<C1>", "<C2>", "<C3>"]`, compressed points.
//! A signing commitment is `{i, D, E}` with `i` the 32-byte identifier hex.

use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare, VerifiableSecretSharingCommitment};
use frost::round1::{NonceCommitment, SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage, VerifyingKey};
use frost::Secp256K1Sha256TR as Suite;
use k256::elliptic_curve::ff::PrimeField;
use k256::Scalar;
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

type Nonce = frost_core::round1::Nonce<Suite>;
type R<T> = Result<T, JsError>;
fn e<E: std::fmt::Debug>(what: &'static str) -> impl Fn(E) -> JsError { move |x| JsError::new(&format!("{what}: {x:?}")) }

#[derive(Serialize, Deserialize, Clone)]
pub struct Commit {
    pub i: String,
    #[serde(rename = "D")]
    pub d: String,
    #[serde(rename = "E")]
    pub e: String,
}

fn bytes<const N: usize>(h: &str, what: &'static str) -> R<[u8; N]> {
    let v = hex::decode(h).map_err(e(what))?;
    v.try_into().map_err(|_| JsError::new(&format!("{what}: expected {N} bytes")))
}
fn id(h: &str) -> R<Identifier> { Identifier::deserialize(&bytes::<32>(h, "identifier")?).map_err(e("identifier")) }
fn scalar(h: &str, what: &'static str) -> R<Scalar> {
    Option::<Scalar>::from(Scalar::from_repr(bytes::<32>(h, what)?.into())).ok_or(JsError::new(&format!("{what}: out of range")))
}

fn commitment(json: &str) -> R<VerifiableSecretSharingCommitment> {
    let pts: Vec<String> = serde_json::from_str(json).map_err(e("commitment"))?;
    let raw = pts.iter().map(|p| hex::decode(p).map_err(e("commitment"))).collect::<R<Vec<_>>>()?;
    VerifiableSecretSharingCommitment::deserialize(raw).map_err(e("commitment"))
}
fn group_key(c: &VerifiableSecretSharingCommitment) -> R<VerifyingKey> {
    let c0 = c.coefficients().first().ok_or(JsError::new("empty commitment"))?;
    let enc = c0.serialize().map_err(e("C0"))?;
    if enc[0] != 0x02 { return Err(JsError::new("C0 must have even y")); }
    VerifyingKey::deserialize(&enc).map_err(e("C0"))
}
fn min_signers(c: &VerifiableSecretSharingCommitment) -> u16 { c.coefficients().len() as u16 }

fn key_package(c: &VerifiableSecretSharingCommitment, i: &str, share: &str) -> R<KeyPackage> {
    let ident = id(i)?;
    let s = SigningShare::deserialize(&bytes::<32>(share, "share")?).map_err(e("share"))?;
    let vs = VerifyingShare::from_commitment(ident, c);
    let kp = KeyPackage::new(ident, s, vs, group_key(c)?, min_signers(c));
    // The share must be the one the commitment names: s·G = P_i^S (§3.4 step 3).
    if VerifyingShare::from(*kp.signing_share()) != vs { return Err(JsError::new("share doesn't match the commitment")); }
    Ok(kp)
}

fn signing_package(msg: &str, commits: &[Commit]) -> R<SigningPackage> {
    let m: [u8; 32] = bytes(msg, "message")?;
    let mut map = BTreeMap::new();
    for c in commits {
        let d = NonceCommitment::deserialize(&bytes::<33>(&c.d, "D")?).map_err(e("D"))?;
        let ee = NonceCommitment::deserialize(&bytes::<33>(&c.e, "E")?).map_err(e("E"))?;
        if map.insert(id(&c.i)?, SigningCommitments::new(d, ee)).is_some() { return Err(JsError::new("repeated index in commitments")); }
    }
    Ok(SigningPackage::new(map, &m))
}

/// A one-shot RNG: SHA-256(hedge ‖ counter) blocks. `nonce_generate` draws 32 bytes per nonce,
/// so a hiding and a binding nonce each get their own block from the one hedge (§5.2).
struct Hedged { seed: [u8; 32], ctr: u32 }
impl RngCore for Hedged {
    fn next_u32(&mut self) -> u32 { let mut b = [0u8; 4]; self.fill_bytes(&mut b); u32::from_be_bytes(b) }
    fn next_u64(&mut self) -> u64 { let mut b = [0u8; 8]; self.fill_bytes(&mut b); u64::from_be_bytes(b) }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            let block = Sha256::new().chain_update(self.seed).chain_update(self.ctr.to_be_bytes()).finalize();
            self.ctr += 1;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> { self.fill_bytes(dest); Ok(()) }
}
impl CryptoRng for Hedged {}

/// The share point `P_i^S` for identifier `i`, compressed hex.
#[wasm_bindgen(js_name = sharePoint)]
pub fn share_point(commitment_json: &str, i: &str) -> R<String> {
    let vs = VerifyingShare::from_commitment(id(i)?, &commitment(commitment_json)?);
    Ok(hex::encode(vs.serialize().map_err(e("point"))?))
}

/// Round 1 for one index: `{"nonces": hex(hiding ‖ binding), "commit": {i, D, E}}`. `hedge` is the
/// 32-byte random input of §5.2. The nonces never leave process memory.
#[wasm_bindgen]
pub fn commit(commitment_json: &str, i: &str, share: &str, hedge: &str) -> R<String> {
    let kp = key_package(&commitment(commitment_json)?, i, share)?;
    let mut rng = Hedged { seed: bytes(hedge, "hedge")?, ctr: 0 };
    let (nonces, c) = frost::round1::commit(kp.signing_share(), &mut rng);
    let n = [nonces.hiding().serialize(), nonces.binding().serialize()].concat();
    let out = serde_json::json!({ "nonces": hex::encode(n), "commit": {
        "i": i, "D": hex::encode(c.hiding().serialize().map_err(e("D"))?), "E": hex::encode(c.binding().serialize().map_err(e("E"))?) } });
    Ok(out.to_string())
}

/// Round 2 for one index: its `z` for `msg` (the 32-byte event id) over every commitment.
#[wasm_bindgen]
pub fn sign(commitment_json: &str, i: &str, share: &str, nonces: &str, msg: &str, commits_json: &str) -> R<String> {
    let kp = key_package(&commitment(commitment_json)?, i, share)?;
    let n: [u8; 64] = bytes(nonces, "nonces")?;
    let nonces = SigningNonces::from_nonces(Nonce::deserialize(&n[..32]).map_err(e("nonce"))?, Nonce::deserialize(&n[32..]).map_err(e("nonce"))?);
    let commits: Vec<Commit> = serde_json::from_str(commits_json).map_err(e("commits"))?;
    let z = frost::round2::sign(&signing_package(msg, &commits)?, &nonces, &kp).map_err(e("sign"))?;
    Ok(hex::encode(z.serialize()))
}

fn public_package(c: &VerifiableSecretSharingCommitment, ids: &[Identifier]) -> R<PublicKeyPackage> {
    let shares = ids.iter().map(|i| (*i, VerifyingShare::from_commitment(*i, c))).collect();
    Ok(PublicKeyPackage::new(shares, group_key(c)?))
}

/// Check one index's `z` against `P_i^S` (`verify_signature_share`).
#[wasm_bindgen(js_name = verifyPartial)]
pub fn verify_partial(commitment_json: &str, msg: &str, commits_json: &str, i: &str, z: &str) -> R<bool> {
    let c = commitment(commitment_json)?;
    let commits: Vec<Commit> = serde_json::from_str(commits_json).map_err(e("commits"))?;
    let ident = id(i)?;
    let ok = (|| -> R<bool> {
        let share = SignatureShare::deserialize(&bytes::<32>(z, "z")?).map_err(e("z"))?;
        let vs = VerifyingShare::from_commitment(ident, &c);
        Ok(frost_core::verify_signature_share(ident, &vs, &share, &signing_package(msg, &commits)?, &group_key(&c)?).is_ok())
    })();
    Ok(ok.unwrap_or(false))
}

/// Aggregate `[[i, z], …]` into a BIP-340 signature (64 bytes hex). Fails unless it verifies.
#[wasm_bindgen]
pub fn aggregate(commitment_json: &str, msg: &str, commits_json: &str, partials_json: &str) -> R<String> {
    let c = commitment(commitment_json)?;
    let commits: Vec<Commit> = serde_json::from_str(commits_json).map_err(e("commits"))?;
    let partials: Vec<(String, String)> = serde_json::from_str(partials_json).map_err(e("partials"))?;
    let mut shares = BTreeMap::new();
    for (i, z) in &partials { shares.insert(id(i)?, SignatureShare::deserialize(&bytes::<32>(z, "z")?).map_err(e("z"))?); }
    let ids: Vec<Identifier> = shares.keys().copied().collect();
    let sig = frost::aggregate(&signing_package(msg, &commits)?, &shares, &public_package(&c, &ids)?).map_err(e("aggregate"))?;
    Ok(hex::encode(sig.serialize().map_err(e("signature"))?))
}

/// Repair step 1 (§4.2 step 3) for one helper index: `[[helper i, delta], …]`, one per helper.
#[wasm_bindgen(js_name = repairStep1)]
pub fn repair_step1(commitment_json: &str, helpers_json: &str, i: &str, share: &str, participant: &str) -> R<String> {
    let c = commitment(commitment_json)?;
    let helpers: Vec<String> = serde_json::from_str(helpers_json).map_err(e("helpers"))?;
    let ids = helpers.iter().map(|h| id(h)).collect::<R<Vec<_>>>()?;
    let kp = key_package(&c, i, share)?;
    let ss = frost::keys::SecretShare::new(kp.identifier().clone(), *kp.signing_share(), c);
    let deltas = frost::keys::repairable::repair_share_step_1::<Suite, OsRng>(&ids, &ss, &mut OsRng, id(participant)?).map_err(e("repair"))?;
    let out = helpers.iter().zip(ids.iter())
        .map(|(h, ident)| Ok((h.clone(), hex::encode(deltas.get(ident).ok_or(JsError::new("delta missing"))?.to_bytes()))))
        .collect::<R<Vec<(String, String)>>>()?;
    Ok(serde_json::to_string(&out).unwrap())
}

/// Repair step 2: a sigma from the deltas meant for one helper index (or several, summed).
#[wasm_bindgen(js_name = repairStep2)]
pub fn repair_step2(deltas_json: &str) -> R<String> {
    let d: Vec<String> = serde_json::from_str(deltas_json).map_err(e("deltas"))?;
    let s = d.iter().map(|x| scalar(x, "delta")).collect::<R<Vec<_>>>()?;
    Ok(hex::encode(frost::keys::repairable::repair_share_step_2(&s).to_bytes()))
}

/// Repair step 3, by the new holder: its share from the sigmas, checked against `P_i^S`.
#[wasm_bindgen(js_name = repairStep3)]
pub fn repair_step3(commitment_json: &str, sigmas_json: &str, participant: &str) -> R<String> {
    let c = commitment(commitment_json)?;
    let d: Vec<String> = serde_json::from_str(sigmas_json).map_err(e("sigmas"))?;
    let s = d.iter().map(|x| scalar(x, "sigma")).collect::<R<Vec<_>>>()?;
    let share = frost::keys::repairable::repair_share_step_3(&s, id(participant)?, &c);
    share.verify().map_err(|_| JsError::new("the repaired share doesn't match the commitment"))?;
    Ok(hex::encode(share.signing_share().serialize()))
}

// --- Distributed key generation (Account admin §1.1), `frost-core`'s `keys::dkg` -------------
//
// One call per participant index; a device runs its five (1, 2, 3 and the backup seat's 5, 6). Secret
// packages cross this API as hex and never leave the participant. The result is brought to even y as
// `frost-secp256k1-tr` does, for the share and every share point.

fn ids_pkgs<T, F: Fn(&[u8]) -> Result<T, frost_core::Error<Suite>>>(json: &str, de: F, what: &'static str) -> R<BTreeMap<Identifier, T>> {
    let v: Vec<(String, String)> = serde_json::from_str(json).map_err(e(what))?;
    v.iter().map(|(i, h)| Ok((id(i)?, de(&hex::decode(h).map_err(e(what))?).map_err(e(what))?))).collect()
}

/// Part 1 for one index: `{"secret", "package"}`. `hedge` seeds the polynomial and proof (§5.2's stream).
#[wasm_bindgen(js_name = dkgPart1)]
pub fn dkg_part1(i: &str, max_signers: u16, min_signers: u16, hedge: &str) -> R<String> {
    let rng = Hedged { seed: bytes(hedge, "hedge")?, ctr: 0 };
    let (secret, package) = frost::keys::dkg::part1(id(i)?, max_signers, min_signers, rng).map_err(e("dkg part 1"))?;
    Ok(serde_json::json!({ "secret": hex::encode(secret.serialize().map_err(e("dkg"))?), "package": hex::encode(package.serialize().map_err(e("dkg"))?) }).to_string())
}

/// Part 2: from every other index's round-1 package (`[[i, package], …]`), a round-2 package for each.
#[wasm_bindgen(js_name = dkgPart2)]
pub fn dkg_part2(secret: &str, others_json: &str) -> R<String> {
    let s = frost::keys::dkg::round1::SecretPackage::deserialize(&hex::decode(secret).map_err(e("secret"))?).map_err(e("secret"))?;
    let others = ids_pkgs(others_json, |b| frost::keys::dkg::round1::Package::deserialize(b), "round 1")?;
    let (s2, pkgs) = frost::keys::dkg::part2(s, &others).map_err(e("dkg part 2"))?;
    let out: Vec<(String, String)> = pkgs.iter().map(|(k, p)| Ok((hex::encode(k.serialize()), hex::encode(p.serialize().map_err(e("dkg"))?)))).collect::<R<_>>()?;
    Ok(serde_json::json!({ "secret": hex::encode(s2.serialize().map_err(e("dkg"))?), "packages": out }).to_string())
}

/// Part 3: `{"share", "groupX", "points": [[i, P_i], …]}`, even y.
#[wasm_bindgen(js_name = dkgPart3)]
pub fn dkg_part3(secret2: &str, round1_json: &str, round2_json: &str) -> R<String> {
    use frost::keys::EvenY;
    let s = frost::keys::dkg::round2::SecretPackage::deserialize(&hex::decode(secret2).map_err(e("secret"))?).map_err(e("secret"))?;
    let r1 = ids_pkgs(round1_json, |b| frost::keys::dkg::round1::Package::deserialize(b), "round 1")?;
    let r2 = ids_pkgs(round2_json, |b| frost::keys::dkg::round2::Package::deserialize(b), "round 2")?;
    let (kp, pkp) = frost::keys::dkg::part3(&s, &r1, &r2).map_err(e("dkg part 3"))?;
    let even = pkp.has_even_y();
    let (kp, pkp) = (kp.into_even_y(Some(even)), pkp.into_even_y(Some(even)));
    let vk = pkp.verifying_key().serialize().map_err(e("key"))?;
    let points: Vec<(String, String)> = pkp.verifying_shares().iter().map(|(k, v)| Ok((hex::encode(k.serialize()), hex::encode(v.serialize().map_err(e("point"))?)))).collect::<R<_>>()?;
    Ok(serde_json::json!({ "share": hex::encode(kp.signing_share().serialize()), "groupX": hex::encode(&vk[1..]), "points": points }).to_string())
}
