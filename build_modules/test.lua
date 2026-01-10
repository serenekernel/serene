function build(build_info)
    local module = {
        name = "test",
        module_type = "custom",
        info = {
            commands = {
                "cd boot_mods/test_rs",
                "cargo build -Z build-std=core --target x86_64-serene.json --release",
                "cp target/x86_64-serene/release/test ../"
            },
            run_mode = "rerun",
        }
    }

    return module
end
