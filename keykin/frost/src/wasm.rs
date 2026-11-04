// The Node/browser bindings (wasm-bindgen): the same calls, errors thrown as JS errors.
use wasm_bindgen::prelude::*;
fn js<T>(r: Result<T, String>) -> Result<T, JsError> { r.map_err(|e| JsError::new(&e)) }

#[wasm_bindgen(js_name = sharePoint)] pub fn share_point(c: &str, i: &str) -> Result<String, JsError> { js(super::share_point(c, i)) }
#[wasm_bindgen] pub fn commit(c: &str, i: &str, share: &str, hedge: &str) -> Result<String, JsError> { js(super::commit(c, i, share, hedge)) }
#[wasm_bindgen] pub fn sign(c: &str, i: &str, share: &str, nonces: &str, msg: &str, commits: &str) -> Result<String, JsError> { js(super::sign(c, i, share, nonces, msg, commits)) }
#[wasm_bindgen(js_name = verifyPartial)] pub fn verify_partial(c: &str, msg: &str, commits: &str, i: &str, z: &str) -> Result<bool, JsError> { js(super::verify_partial(c, msg, commits, i, z)) }
#[wasm_bindgen] pub fn aggregate(c: &str, msg: &str, commits: &str, partials: &str) -> Result<String, JsError> { js(super::aggregate(c, msg, commits, partials)) }
#[wasm_bindgen(js_name = repairStep1)] pub fn repair_step1(c: &str, helpers: &str, i: &str, share: &str, participant: &str) -> Result<String, JsError> { js(super::repair_step1(c, helpers, i, share, participant)) }
#[wasm_bindgen(js_name = repairStep2)] pub fn repair_step2(deltas: &str) -> Result<String, JsError> { js(super::repair_step2(deltas)) }
#[wasm_bindgen(js_name = repairStep3)] pub fn repair_step3(c: &str, sigmas: &str, participant: &str) -> Result<String, JsError> { js(super::repair_step3(c, sigmas, participant)) }
#[wasm_bindgen(js_name = dkgPart1)] pub fn dkg_part1(i: &str, max: u16, min: u16, hedge: &str) -> Result<String, JsError> { js(super::dkg_part1(i, max, min, hedge)) }
#[wasm_bindgen(js_name = dkgPart2)] pub fn dkg_part2(secret: &str, others: &str) -> Result<String, JsError> { js(super::dkg_part2(secret, others)) }
#[wasm_bindgen(js_name = dkgPart3)] pub fn dkg_part3(secret2: &str, r1: &str, r2: &str) -> Result<String, JsError> { js(super::dkg_part3(secret2, r1, r2)) }
