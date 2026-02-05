#![no_main]
use libfuzzer_sys::fuzz_target;
use synergeia_node::script::{evaluate, ScriptContext};

// Fuzzing target to test the robustness of the script interpreter
// against arbitrary byte sequences.
fuzz_target!(|data: &[u8]| {
    // Split the fuzzer input into different components
    if data.len() < 40 {
        return;
    }

    // Use parts of the data to construct the context
    let context = ScriptContext {
        lock_time: u32::from_le_bytes(data[0..4].try_into().unwrap()),
        tx_version: i32::from_le_bytes(data[4..8].try_into().unwrap()),
        input_sequence: u32::from_le_bytes(data[8..12].try_into().unwrap()),
    };

    // Use a fixed pseudo-sighash derived from the data
    let sighash = &data[12..24];
    
    // Split the remaining data into script_sig and script_pub_key
    let mid = 24 + (data.len() - 24) / 2;
    let script_sig = &data[24..mid];
    let script_pub_key = &data[mid..];

    // Execute evaluation - we don't care about the result (true/false),
    // we only care that the interpreter doesn't panic or crash.
    let _ = evaluate(script_sig, script_pub_key, sighash, &context);
});