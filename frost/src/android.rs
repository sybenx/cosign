// The phone's bindings (JNI): cc.aaro.cosign.core.FrostNative. Strings in, strings out;
// errors throw IllegalArgumentException.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jstring};
use jni::JNIEnv;

use super::{Commit, Group};

fn s(env: &mut JNIEnv, j: &JString) -> Result<String, String> {
    env.get_string(j).map(Into::into).map_err(|e| e.to_string())
}
fn group(json: &str) -> Result<Group, String> { serde_json::from_str(json).map_err(|e| format!("group: {e}")) }
fn commits(json: &str) -> Result<Vec<Commit>, String> { serde_json::from_str(json).map_err(|e| format!("commits: {e}")) }

/// Run `f`; hand back its string, or throw.
fn out(env: &mut JNIEnv, r: Result<String, String>) -> jstring {
    match r {
        Ok(v) => env.new_string(v).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(e) => { let _ = env.throw_new("java/lang/IllegalArgumentException", e); std::ptr::null_mut() }
    }
}

#[no_mangle]
pub extern "system" fn Java_cc_aaro_cosign_core_FrostNative_commit(mut env: JNIEnv, _: JClass, g: JString, idx: jint, secret: JString) -> jstring {
    let r = (|| { let g = group(&s(&mut env, &g)?)?; let c = super::commit(&g, idx as u16, &s(&mut env, &secret)?).map_err(|e| e.0)?; Ok(serde_json::to_string(&c).unwrap()) })();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_cc_aaro_cosign_core_FrostNative_sign(mut env: JNIEnv, _: JClass, g: JString, idx: jint, secret: JString, nonces: JString, msg: JString, cs: JString) -> jstring {
    let r = (|| {
        let g = group(&s(&mut env, &g)?)?;
        let cs = commits(&s(&mut env, &cs)?)?;
        super::sign(&g, idx as u16, &s(&mut env, &secret)?, &s(&mut env, &nonces)?, &s(&mut env, &msg)?, &cs).map_err(|e| e.0)
    })();
    out(&mut env, r)
}

#[no_mangle]
pub extern "system" fn Java_cc_aaro_cosign_core_FrostNative_verifyPartial(mut env: JNIEnv, _: JClass, g: JString, msg: JString, cs: JString, idx: jint, z: JString) -> jboolean {
    let r = (|| -> Result<bool, String> {
        let g = group(&s(&mut env, &g)?)?;
        let cs = commits(&s(&mut env, &cs)?)?;
        Ok(super::verify_partial(&g, &s(&mut env, &msg)?, &cs, idx as u16, &s(&mut env, &z)?))
    })();
    r.unwrap_or(false) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_cc_aaro_cosign_core_FrostNative_aggregate(mut env: JNIEnv, _: JClass, g: JString, msg: JString, cs: JString, partials: JString) -> jstring {
    let r = (|| {
        let g = group(&s(&mut env, &g)?)?;
        let cs = commits(&s(&mut env, &cs)?)?;
        let ps: Vec<(u16, String)> = serde_json::from_str(&s(&mut env, &partials)?).map_err(|e| format!("partials: {e}"))?;
        super::aggregate(&g, &s(&mut env, &msg)?, &cs, &ps).map_err(|e| e.0)
    })();
    out(&mut env, r)
}
