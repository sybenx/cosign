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
