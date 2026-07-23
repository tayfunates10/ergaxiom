#![forbid(unsafe_code)]

use std::env;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use ergaxiom_typed_planner_runtime::{
    StaticSocialPostPlanIdentity, TypedPlanOutcome, synthesize_static_social_post_plan,
};
use serde_json::Value;

fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ergaxiom-plan: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<u8, Box<dyn Error>> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if !(3..=4).contains(&arguments.len()) {
        return Err(
            "usage: ergaxiom-plan <plan-identity.json> <work-contract.json> <profession-capsule.json> [output.json]"
                .into(),
        );
    }

    let identity: StaticSocialPostPlanIdentity = read_json(Path::new(&arguments[0]))?;
    let contract: Value = read_json(Path::new(&arguments[1]))?;
    let capsule: Value = read_json(Path::new(&arguments[2]))?;
    let outcome = synthesize_static_social_post_plan(&identity, &contract, &capsule)?;
    let output = serde_json::to_string_pretty(&outcome)?;

    if let Some(path) = arguments.get(3) {
        fs::write(path, format!("{output}\n"))?;
    } else {
        println!("{output}");
    }

    Ok(match outcome {
        TypedPlanOutcome::Planned { .. } => 0,
        TypedPlanOutcome::NeedsResolution { .. } => 2,
    })
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}
