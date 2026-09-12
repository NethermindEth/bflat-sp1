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
    let (public_values, report) = client.execute(elf, stdin).run().expect("execute");

    let got = hex(public_values.as_slice());
    println!("cycles {}", report.total_instruction_count());
    println!("output {}", got);

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
