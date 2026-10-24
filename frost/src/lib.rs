//! Cosign's signing math, on the Zcash Foundation's FROST: RFC 9591 with the
//! secp256k1 BIP-340 ciphersuite (`frost-secp256k1-tr`), so final signatures are plain
//! Nostr signatures under the group key.
//!
//! The API speaks hex and JSON so the server (WebAssembly) and the phone (native) can
//! call it with no shared types. It keeps Cosign's wire shapes: a commitment is
//! `{idx, D, E}` (hiding and binding points, compressed), a partial is a 32-byte `z`.
//!
//! Group: `{ groupX, threshold, members: [{ idx, sharePub }] }`, as servers and phones
//! already store it. Shares made by Cosign's earlier dealer import unchanged: they are
//! Shamir shares at x = idx, and the group key already has an even y.

use std::collections::BTreeMap;

use frost_secp256k1_tr as frost;
use frost::keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare};
use frost::round1::{NonceCommitment, SigningCommitments, SigningNonces};
use frost::Secp256K1Sha256TR as Suite;
type Nonce = frost_core::round1::Nonce<Suite>;
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage, VerifyingKey};
use k256::elliptic_curve::ff::PrimeField;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint, ProjectivePoint, Scalar};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for Error {}
type R<T> = Result<T, Error>;
fn err<E: std::fmt::Debug>(what: &str) -> impl Fn(E) -> Error + '_ { move |e| Error(format!("{what}: {e:?}")) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub idx: u16,
    #[serde(rename = "sharePub")]
    pub share_pub: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    #[serde(rename = "groupX")]
    pub group_x: String,
    pub threshold: u16,
    pub members: Vec<Member>,
}

/// One signer's commitment for a round: its hiding (D) and binding (E) points.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Commit {
    pub idx: u16,
    #[serde(rename = "D")]
    pub d: String,
    #[serde(rename = "E")]
    pub e: String,
}

/// A fresh commitment, and the secret nonces behind it (hiding ‖ binding, hex). Use the
/// nonces for exactly one signature, then forget them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Committed {
    pub nonces: String,
    pub commit: Commit,
}

fn bytes<const N: usize>(hex_str: &str, what: &str) -> R<[u8; N]> {
    let v = hex::decode(hex_str).map_err(err(what))?;
    v.try_into().map_err(|_| Error(format!("{what}: expected {N} bytes")))
}
fn id(idx: u16) -> R<Identifier> { Identifier::try_from(idx).map_err(err("identifier")) }

fn verifying_key(group: &Group) -> R<VerifyingKey> {
    let x: [u8; 32] = bytes(&group.group_x, "groupX")?;
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02; // an x-only key is the even-y point
    sec1[1..].copy_from_slice(&x);
    VerifyingKey::deserialize(&sec1).map_err(err("groupX"))
}

fn public_package(group: &Group) -> R<PublicKeyPackage> {
    let mut shares = BTreeMap::new();
    for m in &group.members {
        let p: [u8; 33] = bytes(&m.share_pub, "sharePub")?;
        shares.insert(id(m.idx)?, VerifyingShare::deserialize(&p).map_err(err("sharePub"))?);
    }
    Ok(PublicKeyPackage::new(shares, verifying_key(group)?))
}

fn key_package(group: &Group, idx: u16, secret: &str) -> R<KeyPackage> {
    let s: [u8; 32] = bytes(secret, "share")?;
    let share = SigningShare::deserialize(&s).map_err(err("share"))?;
    let mine = group.members.iter().find(|m| m.idx == idx).ok_or(Error("not a member".into()))?;
    // The share must be the one the group knows: s·G = sharePub.
    if share_pub(secret)? != mine.share_pub { return Err(Error("share doesn't match the group".into())); }
    let p: [u8; 33] = bytes(&mine.share_pub, "sharePub")?;
    let verifying_share = VerifyingShare::deserialize(&p).map_err(err("sharePub"))?;
    Ok(KeyPackage::new(id(idx)?, share, verifying_share, verifying_key(group)?, group.threshold))
}

fn signing_package(msg: &str, commits: &[Commit]) -> R<SigningPackage> {
    let m: [u8; 32] = bytes(msg, "message")?;
    let mut map = BTreeMap::new();
    for c in commits {
        let d: [u8; 33] = bytes(&c.d, "D")?;
        let e: [u8; 33] = bytes(&c.e, "E")?;
        map.insert(id(c.idx)?, SigningCommitments::new(
            NonceCommitment::deserialize(&d).map_err(err("D"))?,
            NonceCommitment::deserialize(&e).map_err(err("E"))?,
        ));
    }
    Ok(SigningPackage::new(map, &m))
}

/// The public point of a share, compressed hex.
pub fn share_pub(secret: &str) -> R<String> {
    let s = scalar(secret, "share")?;
    Ok(hex::encode((ProjectivePoint::GENERATOR * s).to_affine().to_encoded_point(true).as_bytes()))
}

/// Round 1: fresh nonces and their commitment.
pub fn commit(group: &Group, idx: u16, secret: &str) -> R<Committed> {
    let kp = key_package(group, idx, secret)?;
    let (nonces, commitments) = frost::round1::commit(kp.signing_share(), &mut OsRng);
    let n = [nonces.hiding().serialize(), nonces.binding().serialize()].concat();
    Ok(Committed {
        nonces: hex::encode(n),
        commit: Commit {
            idx,
            d: hex::encode(commitments.hiding().serialize().map_err(err("D"))?),
            e: hex::encode(commitments.binding().serialize().map_err(err("E"))?),
        },
    })
}

/// Round 2: this signer's partial `z` for `msg` (a 32-byte event id) over everyone's commitments.
pub fn sign(group: &Group, idx: u16, secret: &str, nonces: &str, msg: &str, commits: &[Commit]) -> R<String> {
    let kp = key_package(group, idx, secret)?;
    let n: [u8; 64] = bytes(nonces, "nonces")?;
    let nonces = SigningNonces::from_nonces(
        Nonce::deserialize(&n[..32]).map_err(err("nonce"))?,
        Nonce::deserialize(&n[32..]).map_err(err("nonce"))?,
    );
    let share = frost::round2::sign(&signing_package(msg, commits)?, &nonces, &kp).map_err(err("sign"))?;
    Ok(hex::encode(share.serialize()))
}

/// Check one signer's partial before using it.
pub fn verify_partial(group: &Group, msg: &str, commits: &[Commit], idx: u16, z: &str) -> bool {
    let check = || -> R<()> {
        let pk = public_package(group)?;
        let vs = pk.verifying_shares().get(&id(idx)?).ok_or(Error("not a member".into()))?;
        let z: [u8; 32] = bytes(z, "z")?;
        let share = SignatureShare::deserialize(&z).map_err(err("z"))?;
        frost_core::verify_signature_share(id(idx)?, vs, &share, &signing_package(msg, commits)?, pk.verifying_key())
            .map_err(err("partial"))
    };
    check().is_ok()
}

/// Combine partials into the final BIP-340 signature (64 bytes, hex). Fails unless it verifies.
pub fn aggregate(group: &Group, msg: &str, commits: &[Commit], partials: &[(u16, String)]) -> R<String> {
    let mut shares = BTreeMap::new();
    for (idx, z) in partials {
        let z: [u8; 32] = bytes(z, "z")?;
        shares.insert(id(*idx)?, SignatureShare::deserialize(&z).map_err(err("z"))?);
    }
    let sig = frost::aggregate(&signing_package(msg, commits)?, &shares, &public_package(group)?).map_err(err("aggregate"))?;
    Ok(hex::encode(sig.serialize().map_err(err("signature"))?))
}

// --- Adding a device: repair (RTS, frost-core's `repairable`) ------------------------
//
// Two members make a new member's share at a fresh index without either learning it:
// each splits its Lagrange-weighted part of f(k) into random deltas (step 1), sends one
// to the other helper, adds what it holds into a sigma (step 2), and seals the sigma to
// the new device, which adds them (step 3) and checks the result against the group.

/// The group polynomial's public coefficients, rebuilt from any `threshold` share points:
/// each Lagrange basis polynomial's coefficients, applied in the exponent. Its constant
/// term must come out as the group key, which checks the share points too.
fn vss_commitment(group: &Group) -> R<frost::keys::VerifiableSecretSharingCommitment> {
    let t = group.threshold as usize;
    if t < 2 || group.members.len() < t { return Err(Error("not enough share points to rebuild the group's commitment".into())); }
    let pts = group.members.iter().take(t)
        .map(|m| Ok((Scalar::from(m.idx as u64), point(&hex::decode(&m.share_pub).map_err(err("sharePub"))?, "sharePub")?)))
        .collect::<R<Vec<_>>>()?;
    let mut coeffs = vec![ProjectivePoint::IDENTITY; t];
    for (j, (xj, sj)) in pts.iter().enumerate() {
        // L_j(x) = Π_{m≠j} (x − x_m) / (x_j − x_m), as coefficients of x^0..x^(t−1).
        let mut poly = vec![Scalar::ONE];
        let mut den = Scalar::ONE;
        for (m, (xm, _)) in pts.iter().enumerate() {
            if m == j { continue; }
            let mut next = vec![Scalar::ZERO; poly.len() + 1];
            for (i, c) in poly.iter().enumerate() { next[i] -= *c * xm; next[i + 1] += *c; }
            poly = next;
            den *= *xj - xm;
        }
        let inv = Option::<Scalar>::from(den.invert()).ok_or(Error("two share points at one index".into()))?;
        for (i, c) in poly.iter().enumerate() { coeffs[i] += *sj * (*c * inv); }
    }
    let x: [u8; 32] = bytes(&group.group_x, "groupX")?;
    if coeffs[0] != point(&[&[0x02u8][..], &x[..]].concat(), "groupX")? { return Err(Error("the share points don't belong to this key".into())); }
    let enc = |p: &ProjectivePoint| p.to_affine().to_encoded_point(true).as_bytes().to_vec();
    frost::keys::VerifiableSecretSharingCommitment::deserialize(coeffs.iter().map(enc).collect::<Vec<_>>()).map_err(err("commitment"))
}

fn secret_share(group: &Group, idx: u16, secret: &str) -> R<frost::keys::SecretShare> {
    let s: [u8; 32] = bytes(secret, "share")?;
    Ok(frost::keys::SecretShare::new(id(idx)?, SigningShare::deserialize(&s).map_err(err("share"))?, vss_commitment(group)?))
}

/// The share point index `k` will have: the group's commitment evaluated at k.
pub fn share_pub_at(group: &Group, k: u16) -> R<String> {
    let c = vss_commitment(group)?;
    let vs = VerifyingShare::from_commitment(id(k)?, &c);
    Ok(hex::encode(vs.serialize().map_err(err("share point"))?))
}

/// Step 1, by each helper: its deltas, one per helper (keep yours, send the other's).
pub fn repair_step1(group: &Group, idx: u16, secret: &str, helpers: &[u16], participant: u16) -> R<Vec<(u16, String)>> {
    let ids = helpers.iter().map(|h| id(*h)).collect::<R<Vec<_>>>()?;
    let share = secret_share(group, idx, secret)?;
    let deltas = frost::keys::repairable::repair_share_step_1::<Suite, OsRng>(&ids, &share, &mut OsRng, id(participant)?).map_err(err("repair"))?;
    helpers.iter().map(|h| Ok((*h, hex::encode(deltas.get(&id(*h)?).ok_or(Error("delta missing".into()))?.to_bytes())))).collect()
}

/// Step 2, by each helper: its sigma, from the deltas meant for it (its own and the other's).
pub fn repair_step2(deltas: &[String]) -> R<String> {
    let d = deltas.iter().map(|h| scalar(h, "delta")).collect::<R<Vec<_>>>()?;
    Ok(hex::encode(frost::keys::repairable::repair_share_step_2(&d).to_bytes()))
}

/// Step 3, by the new device: its share, from the helpers' sigmas, checked against the group.
pub fn repair_step3(group: &Group, sigmas: &[String], participant: u16) -> R<String> {
    let s = sigmas.iter().map(|h| scalar(h, "sigma")).collect::<R<Vec<_>>>()?;
    let share = frost::keys::repairable::repair_share_step_3(&s, id(participant)?, &vss_commitment(group)?);
    share.verify().map_err(|_| Error("the repaired share doesn't match the group".into()))?;
    Ok(hex::encode(share.signing_share().serialize()))
}

// --- Making a key with nobody holding it: DKG (frost-core's `dkg`) --------------------
//
// Each share's holder runs the three parts (a device with 3 shares runs them 3 times).
// Packages and secrets cross this API as hex; the secrets never leave the holder.
// At the end every share is turned the even-Y way, so the group key is a plain Nostr key.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound { pub secret: String, pub package: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRound2 { pub secret: String, pub packages: Vec<(u16, String)> }
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgDone {
    pub share: String,
    #[serde(rename = "groupX")]
    pub group_x: String,
    pub members: Vec<Member>,
}

/// Part 1, for one share: its secret (keep) and its package (send to every other share).
pub fn dkg_part1(idx: u16, max_signers: u16, min_signers: u16) -> R<DkgRound> {
    let (secret, package) = frost::keys::dkg::part1(id(idx)?, max_signers, min_signers, OsRng).map_err(err("dkg part 1"))?;
    Ok(DkgRound { secret: hex::encode(secret.serialize().map_err(err("dkg"))?), package: hex::encode(package.serialize().map_err(err("dkg"))?) })
}

fn round1_map(packages: &[(u16, String)]) -> R<BTreeMap<Identifier, frost::keys::dkg::round1::Package>> {
    packages.iter().map(|(i, h)| Ok((id(*i)?, frost::keys::dkg::round1::Package::deserialize(&hex::decode(h).map_err(err("package"))?).map_err(err("package"))?))).collect()
}

/// Part 2, for one share: from everyone else's part-1 packages, a package for each of them.
pub fn dkg_part2(secret: &str, others: &[(u16, String)]) -> R<DkgRound2> {
    let s = frost::keys::dkg::round1::SecretPackage::deserialize(&hex::decode(secret).map_err(err("secret"))?).map_err(err("secret"))?;
    let (secret2, packages) = frost::keys::dkg::part2(s, &round1_map(others)?).map_err(err("dkg part 2"))?;
    let mut out = vec![];
    for (who, p) in packages {
        let idx = others.iter().find(|(i, _)| id(*i).ok() == Some(who)).ok_or(Error("unknown recipient".into()))?.0;
        out.push((idx, hex::encode(p.serialize().map_err(err("dkg"))?)));
    }
    Ok(DkgRound2 { secret: hex::encode(secret2.serialize().map_err(err("dkg"))?), packages: out })
}

/// Part 3, for one share: its share, and the group (key and every share point), even-Y.
pub fn dkg_part3(idx: u16, secret2: &str, others_round1: &[(u16, String)], round2_received: &[(u16, String)]) -> R<DkgDone> {
    use frost::keys::EvenY;
    let s = frost::keys::dkg::round2::SecretPackage::deserialize(&hex::decode(secret2).map_err(err("secret"))?).map_err(err("secret"))?;
    let r2 = round2_received.iter().map(|(i, h)| Ok((id(*i)?, frost::keys::dkg::round2::Package::deserialize(&hex::decode(h).map_err(err("package"))?).map_err(err("package"))?)))
        .collect::<R<BTreeMap<_, _>>>()?;
    let (kp, pkp) = frost::keys::dkg::part3(&s, &round1_map(others_round1)?, &r2).map_err(err("dkg part 3"))?;
    let even = pkp.has_even_y();
    let (kp, pkp) = (kp.into_even_y(Some(even)), pkp.into_even_y(Some(even)));
    let vk = pkp.verifying_key().serialize().map_err(err("key"))?;
    let mut idxs: Vec<u16> = others_round1.iter().map(|(i, _)| *i).collect();
    idxs.push(idx);
    let mut members = vec![];
    for (who, vs) in pkp.verifying_shares() {
        let idx = idxs.iter().copied().find(|i| id(*i).ok() == Some(*who)).ok_or(Error("unknown share".into()))?;
        members.push(Member { idx, share_pub: hex::encode(vs.serialize().map_err(err("share point"))?) });
    }
    members.sort_by_key(|m| m.idx);
    Ok(DkgDone { share: hex::encode(kp.signing_share().serialize()), group_x: hex::encode(&vk[1..]), members })
}

// --- Decryption: threshold ECDH (not part of FROST) --------------------------------
//
// Each of two members returns λ_i·s_i·P for the peer's key P; the sum is s·P, the shared
// point NIP-04 and NIP-44 need. The same math Cosign used before.

fn scalar(h: &str, what: &str) -> R<Scalar> {
    let b: [u8; 32] = bytes(h, what)?;
    Option::<Scalar>::from(Scalar::from_repr(b.into())).ok_or(Error(format!("{what}: out of range")))
}

fn lagrange(idx: u16, participants: &[u16]) -> R<Scalar> {
    let xi = Scalar::from(idx as u64);
    let (mut num, mut den) = (Scalar::ONE, Scalar::ONE);
    for &j in participants {
        if j == idx { continue; }
        let xj = Scalar::from(j as u64);
        num *= xj;
        den *= xj - xi;
    }
    Option::<Scalar>::from(den.invert()).map(|inv| num * inv).ok_or(Error("bad participants".into()))
}

fn point(sec1: &[u8], what: &str) -> R<ProjectivePoint> {
    let ep = EncodedPoint::from_bytes(sec1).map_err(err(what))?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep)).map(ProjectivePoint::from).ok_or(Error(format!("{what}: not on the curve")))
}

/// This member's part of the shared point with `peer_x` (compressed hex).
pub fn ecdh_partial(idx: u16, secret: &str, participants: &[u16], peer_x: &str) -> R<String> {
    let x: [u8; 32] = bytes(peer_x, "peer")?;
    let peer = point(&[&[0x02u8][..], &x[..]].concat(), "peer")?;
    let k = lagrange(idx, participants)? * scalar(secret, "share")?;
    Ok(hex::encode((peer * k).to_affine().to_encoded_point(true).as_bytes()))
}

/// The shared x coordinate from two members' parts (hex).
pub fn ecdh_combine(parts: &[String]) -> R<String> {
    let mut sum = ProjectivePoint::IDENTITY;
    for p in parts { sum += point(&hex::decode(p).map_err(err("point"))?, "point")?; }
    let enc = sum.to_affine().to_encoded_point(false);
    Ok(hex::encode(enc.x().ok_or(Error("shared point is infinity".into()))?))
}

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(feature = "android")]
mod android;

#[cfg(test)]
mod tests;
