use std::path::Path;

fn main() {
    build_test_cases();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let cases_dir = format!("cargo:rerun-if-changed={}/tests/cases/", manifest_dir);
    println!("cargo:rerun-if-changed={cases_dir}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.lock");
}

fn build_test_cases() {
    let zig_freestanding_target = "aarch64-freestanding-none";
    let zig_target_static = "aarch64-linux-musl";
    let zig_target_dynamic = "aarch64-linux-gnu";

    // Search all *.S files in the asm/ directory and compile them with zig cc:
    for entry in std::fs::read_dir("tests/cases/asm").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            continue;
        }
        // The assembly file is in the format of foo_${arch}.S, so we need to check if ${arch} matches.
        let file_name_without_ext = path.file_stem().unwrap().to_str().unwrap();
        let ext = path.extension().unwrap();
        if ext != "S" {
            continue;
        }

        // Create the output path in cases/${arch}/${file_name without extension}:
        let exe_path_str = format!("tests/cases/asm/{file_name_without_ext}.exe");
        let exe_path = Path::new(exe_path_str.as_str());

        // Check if the source file is newer than the executable, and if not, skip it:
        // Instead of add arch as a extension, add arch as a subdirectory:
        if exe_path.exists() {
            let exe_metadata = exe_path.metadata().unwrap();
            let src_metadata = path.metadata().unwrap();
            if exe_metadata.modified().unwrap() > src_metadata.modified().unwrap() {
                continue;
            }
        }

        // Compile the file with zig cc.
        let mut cmd = std::process::Command::new("zig");
        cmd.arg("cc")
            .arg("-target")
            .arg(zig_freestanding_target)
            .arg("-g")
            .arg("-static")
            .arg("-o")
            .arg(exe_path)
            .arg(path);
        println!("running: {:?}", cmd);
        let status = cmd.status().unwrap();
        assert!(status.success());
    }

    // Search all *.c files in the cases/ directory and compile them with zig cc:
    for entry in std::fs::read_dir("tests/cases/c").unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        let ext = path.extension().unwrap();
        if ext != "c" {
            continue;
        }

        // Create the output path in cases/${arch}/${file_name without extension}:
        let exe_path_str = format!(
            "tests/cases/c/{}.exe",
            path.file_stem().unwrap().to_str().unwrap()
        );
        let dynamic_exe_path_str = format!(
            "tests/cases/c/{}.dynamic.exe",
            path.file_stem().unwrap().to_str().unwrap()
        );

        let exe_path = Path::new(exe_path_str.as_str());
        let exe_path_dynamic = Path::new(dynamic_exe_path_str.as_str());

        // Compile the file with zig static target.
        let mut cmd = std::process::Command::new("zig");
        cmd.arg("cc")
            .arg("-target")
            .arg(zig_target_static)
            .arg("-g")
            .arg("-static")
            .arg("-O0")
            .arg("-o")
            .arg(exe_path)
            .arg(path.clone());
        println!("running: {:?}", cmd);
        let status = cmd.status().unwrap();
        assert!(status.success());

        // Compile the file with zig dynamic target.
        let mut cmd = std::process::Command::new("zig");
        cmd.arg("cc")
            .arg("-target")
            .arg(zig_target_dynamic)
            .arg("-g")
            .arg("-o")
            .arg(exe_path_dynamic)
            .arg(path);
        println!("running: {:?}", cmd);
        let status = cmd.status().unwrap();
        assert!(status.success());
    }
}
