#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use ergaxiom_intent_contract_compiler_runtime::{
    IntentCompileOutcome, StaticSocialPostIntent, compile_static_social_post_intent,
};
use serde_json::Value;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ergaxiom-contract-compile: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err(
            "usage: ergaxiom-contract-compile <intent.json> <profession-capsule.json> [output.json]"
                .into(),
        );
    }

    let intent: StaticSocialPostIntent = read_json(Path::new(&arguments[0]))?;
    let capsule: Value = read_json(Path::new(&arguments[1]))?;
    let outcome = compile_static_social_post_intent(&intent, &capsule)?;
    let output = serde_json::to_string_pretty(&outcome)?;

    if let Some(path) = arguments.get(2) {
        fs::write(path, format!("{output}\n"))?;
    } else {
        println!("{output}");
    }

    Ok(match outcome {
        IntentCompileOutcome::Compiled { .. } => 0,
        IntentCompileOutcome::NeedsResolution { .. } => 2,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}
