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
