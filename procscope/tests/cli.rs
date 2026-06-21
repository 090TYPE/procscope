use std::process::Command;

#[test]
fn shows_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_procscope"))
        .arg("--help")
        .output()
        .expect("run procscope --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("--pid"), "help mentions --pid");
    assert!(text.contains("procscope"), "help mentions binary name");
}
