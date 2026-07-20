use std::{env, error::Error, fs, io, path::Path, process::ExitCode};

use ergaxiom_contract_runtime::compile_contract;
use serde_json::{Value, json};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("CONTRACT COMPILATION FAILED\n{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args_os();
    let program = arguments
        .next()
        .unwrap_or_else(|| "ergaxiom-contract-check".into());
    let contract_path = arguments.next().ok_or_else(|| usage_error(&program))?;
    let capsule_path = arguments.next().ok_or_else(|| usage_error(&program))?;
    if arguments.next().is_some() {
        return Err(usage_error(&program).into());
    }

    let contract = load_json(Path::new(&contract_path))?;
    let capsule = load_json(Path::new(&capsule_path))?;
    let compiled = compile_contract(&contract, &capsule)?;

    let summary = json!({
        "status": "COMPILED",
        "contract_id": compiled.contract_id,
        "job_type": compiled.job_type,
        "contract_digest": compiled.seal.contract_digest,
        "capsule_digest": compiled.seal.capsule_digest,
        "schema_version": compiled.seal.schema_version,
        "minimum_assurance_level": compiled.minimum_assurance_level,
        "unresolved_mandatory_unknowns": compiled.unresolved_mandatory_unknowns,
        "proof_obligations": compiled.proof_obligation_count()
    });
    println!("{}", serde_json::to_string_pretty(&summary)?);
    Ok(())
}

fn load_json(path: &Path) -> Result<Value, Box<dyn Error>> {
    let source = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&source)?)
}

fn usage_error(program: &std::ffi::OsStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!(
            "usage: {} <work-contract.json> <profession-capsule.json>",
            program.to_string_lossy()
        ),
    )
}
