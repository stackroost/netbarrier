use xshell::{cmd, Shell};
use anyhow::Result;

fn main() -> Result<()> {
    let sh = Shell::new()?;

    println!("🔨 Building ssh_session_monitor...");

    cmd!(
        sh,
        "cargo +nightly rustc -p ssh_session_monitor --release --target bpfel-unknown-none -Z build-std=core -- --emit=llvm-bc"
    )
    .run()?;

    let bc_path = sh
        .read_dir("ebpf-programs/ssh_session_monitor/target/bpfel-unknown-none/release/deps")?
        .into_iter()
        .find(|p| p.extension().map_or(false, |ext| ext == "bc"))
        .expect("LLVM bitcode (.bc) file not found");

    sh.create_dir("bin")?;

    let output = "bin/ssh_session_monitor.o";

    println!("📦 Converting .bc -> .o: {output}");

    cmd!(sh, "llc-20 -march=bpf -filetype=obj -o {output} {bc_path}").run()?;

    println!("✅ Done.");
    Ok(())
}
