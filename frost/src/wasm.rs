// The server's bindings (WebAssembly, for Node): JSON in, JSON or hex out. Errors throw.

use wasm_bindgen::prelude::*;
use super::{Commit, Group};

fn group(json: &str) -> Result<Group, JsError> { serde_json::from_str(json).map_err(|e| JsError::new(&format!("group: {e}"))) }
fn commits(json: &str) -> Result<Vec<Commit>, JsError> { serde_json::from_str(json).map_err(|e| JsError::new(&format!("commits: {e}"))) }
fn js<T>(r: super::R<T>) -> Result<T, JsError> { r.map_err(|e| JsError::new(&e.0)) }

#[wasm_bindgen(js_name = sharePub)]
pub fn share_pub(secret: &str) -> Result<String, JsError> { js(super::share_pub(secret)) }

/// Returns `{"nonces": hex, "commit": {"idx", "D", "E"}}`.
#[wasm_bindgen]
pub fn commit(group_json: &str, idx: u16, secret: &str) -> Result<String, JsError> {
    Ok(serde_json::to_string(&js(super::commit(&group(group_json)?, idx, secret))?).unwrap())
}

#[wasm_bindgen]
pub fn sign(group_json: &str, idx: u16, secret: &str, nonces: &str, msg: &str, commits_json: &str) -> Result<String, JsError> {
    js(super::sign(&group(group_json)?, idx, secret, nonces, msg, &commits(commits_json)?))
}

#[wasm_bindgen(js_name = verifyPartial)]
pub fn verify_partial(group_json: &str, msg: &str, commits_json: &str, idx: u16, z: &str) -> Result<bool, JsError> {
    Ok(super::verify_partial(&group(group_json)?, msg, &commits(commits_json)?, idx, z))
}

/// `partials_json`: `[[idx, z], …]`.
#[wasm_bindgen]
pub fn aggregate(group_json: &str, msg: &str, commits_json: &str, partials_json: &str) -> Result<String, JsError> {
    let partials: Vec<(u16, String)> = serde_json::from_str(partials_json).map_err(|e| JsError::new(&format!("partials: {e}")))?;
    js(super::aggregate(&group(group_json)?, msg, &commits(commits_json)?, &partials))
}

#[wasm_bindgen(js_name = ecdhPartial)]
pub fn ecdh_partial(idx: u16, secret: &str, participants: Vec<u16>, peer_x: &str) -> Result<String, JsError> {
    js(super::ecdh_partial(idx, secret, &participants, peer_x))
}

#[wasm_bindgen(js_name = ecdhCombine)]
pub fn ecdh_combine(parts: Vec<String>) -> Result<String, JsError> { js(super::ecdh_combine(&parts)) }

#[wasm_bindgen(js_name = sharePubAt)]
pub fn share_pub_at(group_json: &str, k: u16) -> Result<String, JsError> { js(super::share_pub_at(&group(group_json)?, k)) }

/// Returns `[[helperIdx, delta], …]`.
#[wasm_bindgen(js_name = repairStep1)]
pub fn repair_step1(group_json: &str, idx: u16, secret: &str, helpers: Vec<u16>, participant: u16) -> Result<String, JsError> {
    Ok(serde_json::to_string(&js(super::repair_step1(&group(group_json)?, idx, secret, &helpers, participant))?).unwrap())
}

#[wasm_bindgen(js_name = repairStep2)]
pub fn repair_step2(deltas: Vec<String>) -> Result<String, JsError> { js(super::repair_step2(&deltas)) }

#[wasm_bindgen(js_name = repairStep3)]
pub fn repair_step3(group_json: &str, sigmas: Vec<String>, participant: u16) -> Result<String, JsError> {
    js(super::repair_step3(&group(group_json)?, &sigmas, participant))
}

/// DKG part 1 for one share: `{"secret", "package"}`.
#[wasm_bindgen(js_name = dkgPart1)]
pub fn dkg_part1(idx: u16, max_signers: u16, min_signers: u16) -> Result<String, JsError> {
    Ok(serde_json::to_string(&js(super::dkg_part1(idx, max_signers, min_signers))?).unwrap())
}

/// DKG part 2: `others` is `[[idx, package], …]`. Returns `{"secret", "packages": [[toIdx, package], …]}`.
#[wasm_bindgen(js_name = dkgPart2)]
pub fn dkg_part2(secret: &str, others_json: &str) -> Result<String, JsError> {
    let others: Vec<(u16, String)> = serde_json::from_str(others_json).map_err(|e| JsError::new(&format!("packages: {e}")))?;
    Ok(serde_json::to_string(&js(super::dkg_part2(secret, &others))?).unwrap())
}

/// DKG part 3: returns `{"share", "groupX", "members": [{idx, sharePub}, …]}`.
#[wasm_bindgen(js_name = dkgPart3)]
pub fn dkg_part3(idx: u16, secret2: &str, others_round1_json: &str, round2_json: &str) -> Result<String, JsError> {
    let r1: Vec<(u16, String)> = serde_json::from_str(others_round1_json).map_err(|e| JsError::new(&format!("round 1: {e}")))?;
    let r2: Vec<(u16, String)> = serde_json::from_str(round2_json).map_err(|e| JsError::new(&format!("round 2: {e}")))?;
    Ok(serde_json::to_string(&js(super::dkg_part3(idx, secret2, &r1, &r2))?).unwrap())
}
