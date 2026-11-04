// The JVM and Android bindings (JNI): one entry point, keykin.FrostNative.call(name, argsJson),
// so the Kotlin side mirrors the wasm API by name. Errors throw IllegalArgumentException.
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

fn dispatch(name: &str, a: &[String]) -> Result<String, String> {
    let n = |k: usize| a.get(k).map(String::as_str).ok_or_else(|| format!("{name}: missing argument {k}"));
    let u = |k: usize| n(k)?.parse::<u16>().map_err(|e| format!("{name}: {e}"));
    match name {
        "sharePoint" => super::share_point(n(0)?, n(1)?),
        "commit" => super::commit(n(0)?, n(1)?, n(2)?, n(3)?),
        "sign" => super::sign(n(0)?, n(1)?, n(2)?, n(3)?, n(4)?, n(5)?),
        "verifyPartial" => super::verify_partial(n(0)?, n(1)?, n(2)?, n(3)?, n(4)?).map(|b| b.to_string()),
        "aggregate" => super::aggregate(n(0)?, n(1)?, n(2)?, n(3)?),
        "repairStep1" => super::repair_step1(n(0)?, n(1)?, n(2)?, n(3)?, n(4)?),
        "repairStep2" => super::repair_step2(n(0)?),
        "repairStep3" => super::repair_step3(n(0)?, n(1)?, n(2)?),
        "dkgPart1" => super::dkg_part1(n(0)?, u(1)?, u(2)?, n(3)?),
        "dkgPart2" => super::dkg_part2(n(0)?, n(1)?),
        "dkgPart3" => super::dkg_part3(n(0)?, n(1)?, n(2)?),
        _ => Err(format!("unknown call {name}")),
    }
}

#[no_mangle]
pub extern "system" fn Java_keykin_FrostNative_call(mut env: JNIEnv, _: JClass, name: JString, args: JString) -> jstring {
    let r = (|| -> Result<String, String> {
        let name: String = env.get_string(&name).map_err(|e| e.to_string())?.into();
        let args: String = env.get_string(&args).map_err(|e| e.to_string())?.into();
        let a: Vec<String> = serde_json::from_str(&args).map_err(|e| format!("args: {e}"))?;
        dispatch(&name, &a)
    })();
    match r {
        Ok(v) => env.new_string(v).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
        Err(e) => { let _ = env.throw_new("java/lang/IllegalArgumentException", e); std::ptr::null_mut() }
    }
}
