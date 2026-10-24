// Shares from Cosign's earlier dealer (android/app/src/test/resources/frost.json) sign
// with the library and give signatures that verify as plain BIP-340 under the group key.

use super::*;
use k256::schnorr::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey as SchnorrKey};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../android/app/src/test/resources/frost.json")).unwrap()
}

fn group_of(v: &serde_json::Value) -> (Group, Vec<(u16, String)>) {
    let shares = v["shares"].as_array().unwrap();
    let members = shares.iter().map(|s| Member { idx: s["idx"].as_u64().unwrap() as u16, share_pub: s["pub"].as_str().unwrap().into() }).collect();
    let secrets = shares.iter().map(|s| (s["idx"].as_u64().unwrap() as u16, s["secret"].as_str().unwrap().to_string())).collect();
    (Group { group_x: v["groupX"].as_str().unwrap().into(), threshold: 2, members }, secrets)
}

fn bip340_ok(group_x: &str, msg: &str, sig: &str) -> bool {
    let key = SchnorrKey::from_bytes(&hex::decode(group_x).unwrap()).unwrap();
    let sig = Signature::try_from(hex::decode(sig).unwrap().as_slice()).unwrap();
    key.verify_prehash(&hex::decode(msg).unwrap(), &sig).is_ok()
}

#[test]
fn old_shares_sign_with_every_pair() {
    let (group, secrets) = group_of(&vectors());
    for (a, b) in [(1u16, 2u16), (1, 3), (2, 3)] {
        for round in 0..8 {
            let msg = hex::encode([round as u8 + a as u8 * 16 + b as u8; 32]);
            let sa = &secrets.iter().find(|s| s.0 == a).unwrap().1;
            let sb = &secrets.iter().find(|s| s.0 == b).unwrap().1;
            let ca = commit(&group, a, sa).unwrap();
            let cb = commit(&group, b, sb).unwrap();
            let commits = vec![ca.commit.clone(), cb.commit.clone()];
            let za = sign(&group, a, sa, &ca.nonces, &msg, &commits).unwrap();
            let zb = sign(&group, b, sb, &cb.nonces, &msg, &commits).unwrap();
            assert!(verify_partial(&group, &msg, &commits, a, &za));
            assert!(verify_partial(&group, &msg, &commits, b, &zb));
            assert!(!verify_partial(&group, &msg, &commits, a, &zb), "a partial from the wrong member must fail");
            let sig = aggregate(&group, &msg, &commits, &[(a, za), (b, zb)]).unwrap();
            assert!(bip340_ok(&group.group_x, &msg, &sig), "pair {a},{b} round {round}");
        }
    }
}

#[test]
fn a_share_that_isnt_yours_is_refused() {
    let (group, secrets) = group_of(&vectors());
    assert!(commit(&group, 1, &secrets[1].1).is_err());
}

#[test]
fn ecdh_matches_the_earlier_math() {
    let v = vectors();
    let (_, secrets) = group_of(&v);
    for e in v["ecdh"].as_array().unwrap() {
        let idx = e["idx"].as_u64().unwrap() as u16;
        let parts: Vec<u16> = e["participants"].as_array().unwrap().iter().map(|p| p.as_u64().unwrap() as u16).collect();
        let secret = &secrets.iter().find(|s| s.0 == idx).unwrap().1;
        assert_eq!(ecdh_partial(idx, secret, &parts, e["peerX"].as_str().unwrap()).unwrap(), e["expect"].as_str().unwrap());
    }
}

#[test]
fn ecdh_two_parts_make_the_shared_secret() {
    let (_, secrets) = group_of(&vectors());
    // The group's secret, from shares 1 and 2, against a peer we know the key of.
    let s1 = scalar(&secrets[0].1, "s").unwrap();
    let s2 = scalar(&secrets[1].1, "s").unwrap();
    let group_secret = lagrange(1, &[1, 2]).unwrap() * s1 + lagrange(2, &[1, 2]).unwrap() * s2;
    let peer_secret = Scalar::from(123456789u64);
    let peer = (ProjectivePoint::GENERATOR * peer_secret).to_affine().to_encoded_point(true);
    let peer_x = hex::encode(&peer.as_bytes()[1..]);
    let parts = vec![ecdh_partial(1, &secrets[0].1, &[1, 2], &peer_x).unwrap(), ecdh_partial(2, &secrets[1].1, &[1, 2], &peer_x).unwrap()];
    let shared = ecdh_combine(&parts).unwrap();
    // x(s·P) is the same whichever of ±P was lifted.
    let expect = (ProjectivePoint::GENERATOR * (group_secret * peer_secret)).to_affine().to_encoded_point(false);
    assert_eq!(shared, hex::encode(expect.x().unwrap()));
}

#[test]
fn repair_makes_a_new_member_that_signs() {
    let (group, secrets) = group_of(&vectors());
    let sec = |i: u16| secrets.iter().find(|s| s.0 == i).unwrap().1.clone();
    // Helpers 1 and 3 make member 4's share.
    let d1 = repair_step1(&group, 1, &sec(1), &[1, 3], 4).unwrap();
    let d3 = repair_step1(&group, 3, &sec(3), &[1, 3], 4).unwrap();
    let get = |d: &Vec<(u16, String)>, i: u16| d.iter().find(|x| x.0 == i).unwrap().1.clone();
    let sigma1 = repair_step2(&[get(&d1, 1), get(&d3, 1)]).unwrap();
    let sigma3 = repair_step2(&[get(&d1, 3), get(&d3, 3)]).unwrap();
    let s4 = repair_step3(&group, &[sigma1, sigma3], 4).unwrap();
    assert_eq!(share_pub(&s4).unwrap(), share_pub_at(&group, 4).unwrap());
    // Neither helper's sigma is the share.
    assert_ne!(s4, get(&d1, 1));
    // And it signs with an old member.
    let mut g = group.clone();
    g.members.push(Member { idx: 4, share_pub: share_pub(&s4).unwrap() });
    let msg = hex::encode([7u8; 32]);
    let c4 = commit(&g, 4, &s4).unwrap();
    let c2 = commit(&g, 2, &sec(2)).unwrap();
    let commits = vec![c4.commit.clone(), c2.commit.clone()];
    let z4 = sign(&g, 4, &s4, &c4.nonces, &msg, &commits).unwrap();
    let z2 = sign(&g, 2, &sec(2), &c2.nonces, &msg, &commits).unwrap();
    let sig = aggregate(&g, &msg, &commits, &[(4, z4), (2, z2)]).unwrap();
    assert!(bip340_ok(&g.group_x, &msg, &sig));
}

#[test]
fn a_wrong_sigma_is_caught() {
    let (group, secrets) = group_of(&vectors());
    let sec = |i: u16| secrets.iter().find(|s| s.0 == i).unwrap().1.clone();
    let d1 = repair_step1(&group, 1, &sec(1), &[1, 3], 4).unwrap();
    let sigma1 = repair_step2(&[d1[0].1.clone()]).unwrap(); // missing the other helper's delta
    assert!(repair_step3(&group, &[sigma1, hex::encode([1u8; 32])], 4).is_err());
}
