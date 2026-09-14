use std::fs;
use sp1_sdk::blocking::{prelude::*, ProverClient};

fn main() {
    let mut args = std::env::args().skip(1);
    let elf_path = args.next().expect("usage: sp1runner <elf> <input> [<expected-hex>]");
    let input_path = args.next().expect("usage: sp1runner <elf> <input> [<expected-hex>]");
    let expected = args.next();

    let elf = Elf::from(fs::read(&elf_path).expect("elf"));
    let input = fs::read(&input_path).expect("input");

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input);

    let client = ProverClient::builder().cpu().build();
    let (public_values, report) = match client.execute(elf, stdin).run() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("execute failed: {e}");
            std::process::exit(1);
        }
    };

    let got = hex(public_values.as_slice());
    println!("cycles {}", report.total_instruction_count());
    println!("exit_code {}", report.exit_code);
    println!("output {}", got);

    // A guest that halts non-zero is a failed run, and SP1 does NOT report that
    // as an execution error - it completes normally and leaves the code in the
    // report. Without this, every failure of the guest (including the trap
    // modules' 253/254/255) looked like a pass to the caller.
    if report.exit_code != 0 {
        eprintln!("guest halted with exit code {}", report.exit_code);
        std::process::exit(1);
    }

    if let Some(want) = expected {
        if got != want {
            eprintln!("MISMATCH\n  got  {got}\n  want {want}");
            std::process::exit(1);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
