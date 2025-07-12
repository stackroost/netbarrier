use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use anyhow::{bail, Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Args {
    BuildEbpf,
}

fn main() -> Result<()> {
    match Args::parse() {
        Args::BuildEbpf => build_ssh_session_monitor(),
    }
}

fn build_ssh_session_monitor() -> Result<()> {
    let crate_name = "udp_monitor";
    let target = "bpfel-unknown-none";
    let deps_dir = Path::new("target").join(target).join("release").join("deps");

    let output_bitcode: PathBuf;
    let final_output = Path::new("../../bin/udp_monitor.o");

    println!("[1/3] Building {crate_name} with `cargo rustc`...");

    let status = Command::new("cargo")
        .args([
            "+nightly",
            "rustc",
            "--release",
            "--target",
            target,
            "-Z",
            "build-std=core",
            "-p",
            crate_name,
            "--",
            "--emit=obj",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to run cargo rustc")?;

    if !status.success() {
        bail!("Build failed for {crate_name}");
    }

    println!("\nSearching for LLVM bitcode .o in {}", deps_dir.display());

    let candidates: Vec<_> = fs::read_dir(&deps_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().map(|ext| ext == "o").unwrap_or(false)
                && path.file_name()
                    .map(|name| name.to_string_lossy().contains("udp_monitor"))
                    .unwrap_or(false)
        })
        .collect();

    if candidates.is_empty() {
        bail!(
            "No matching .o files found for crate in {}",
            deps_dir.display()
        );
    }

    output_bitcode = candidates[0].clone();

    println!("Found: {}", output_bitcode.display());

    println!("\n[2/3] Compiling bitcode to BPF ELF with llc-20...");

    let status = Command::new("llc-20")
        .args([
            "-march=bpf",
            "-filetype=obj",
            "-o",
            final_output.to_str().unwrap(),
            output_bitcode.to_str().unwrap(),
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .context("Failed to execute llc-20")?;

    if !status.success() {
        bail!("llc-20 failed to generate final ELF file.");
    }

    println!(
        "Done: Final ELF written to {}",
        final_output.display()
    );

    Ok(())
}
