function table_extend(table1, table2)
    for _, elem in ipairs(table2) do
        table.insert(table1, elem)
    end
end

function tbl_tostring(tbl, indent)
    local s = "{\n"

    indent = indent + 2

    for k, v in pairs(tbl) do
        for i = 1, indent do
            s = s .. "  "
        end

        if v == nil then
            v = "nil"
        elseif type(v) == "table" then
            v = tbl_tostring(v, indent)
        elseif type(v) == "string" then
            v = '"' .. v .. '"'
        else
            v = tostring(v)
        end
        s = s .. tostring(k) .. "=" .. v .. ", \n"
    end

    s = s:sub(1, #s - 3) .. "\n"
    indent = indent - 2
    for i = 1, indent do
        s = s .. "  "
    end
    s = s .. "}"
    return s
end

function build(build_info)
    local sources = glob("kernel/src/**/*.c", "kernel/src/arch/**/*.c")
    table_extend(sources, glob("kernel/deps/flanterm/src/**/*.c"))
    table_extend(sources, glob("kernel/src/arch/" .. (build_info.target_architecture or "x86_64") .. "/**/*.c"))
    if build_info.target_architecture == "x86_64" then
        table_extend(sources, glob("kernel/src/arch/x86_64/**/*.asm"))
    end
    print(tbl_tostring(sources, 0))
    local kernel_module = {
        name = "kernel",
        module_type = "executable",
        depends_on = { },

        info = {
            output = "kernel-" .. (build_info.target_architecture or "x86_64"),
            sources = sources,
            gen_deps = true,
            c_compiler_binary = "",
            ld_binary = "",

            c_flags = {
                "-Wall",
                "-Wextra",
                "-Werror",
                "-std=gnu23",
                "-nostdinc",
                "-ffreestanding",
                "-fno-stack-protector",
                "-fno-stack-check",
                "-fno-lto",
                "-fno-PIC",
                "-ffunction-sections",
                "-fdata-sections",
                "-g",
                
                "-pipe",
                "-O2",
                
                "-fno-omit-frame-pointer",
                "-mno-omit-leaf-frame-pointer",
                
                "-Ikernel/include/",
                "-Ikernel/deps/limine-protocol/include",
                "-Ikernel/deps/flanterm/src",
                "-isystemkernel/deps/freestnd-c-hdrs/include",
                "-MMD",
                "-MP"
            },
            asm_flags = {
                "-f elf64",
                "-g",
                "-Wall",
                "-F dwarf"
            },
            ld_flags = {
                "-nostdlib",
                "-static", 
                "-z max-page-size=0x1000", 
                "--gc-sections", 
                "-Tlinker-scripts/" .. (build_info.target_architecture or "x86_64") .. ".lds"
            }
        }
    }

    if build_info.target_architecture == nil then
        build_info.target_architecture = "x86_64"
    end
    if build_info.target_compiler == nil then
        build_info.target_compiler = "clang"
    end

    if build_info.target_architecture == "x86_64" then
        kernel_module.info.asm_binary = "nasm"
    end

    if build_info.target_compiler == "gcc" then
        kernel_module.info.c_compiler_binary = build_info.target_architecture .. "-elf-gcc"
        kernel_module.info.ld_binary         = build_info.target_architecture .. "-elf-ld"
    elseif build_info.target_compiler == "clang" then
        kernel_module.info.ld_binary         = "ld.lld"
        kernel_module.info.c_compiler_binary = "clang"
        kernel_module.info.c_flags           = { "--target=" .. build_info.target_architecture .. "-none-elf", table.unpack(kernel_module.info.c_flags) }
    else
        error("Unsupported compiler: " .. build_info.target_compiler)
    end

    if build_info.target_architecture == "x86_64" then
        kernel_module.info.c_flags = { "-D__ARCH_X86_64__", table.unpack(kernel_module.info.c_flags) }
    elseif build_info.target_architecture == "aarch64" then
        kernel_module.info.c_flags = { "-D__ARCH_AARCH64__", table.unpack(kernel_module.info.c_flags) }
    elseif build_info.target_architecture == "riscv64" then
        kernel_module.info.c_flags = { "-D__ARCH_RISCV64__", table.unpack(kernel_module.info.c_flags) }
    elseif build_info.target_architecture == "loongarch64" then
        kernel_module.info.c_flags = { "-D__ARCH_LOONGARCH64__", table.unpack(kernel_module.info.c_flags) }
    end

    local arch_flags = {
        x86_64 = {
            c_flags = { "-m64", "-march=x86-64", "-mabi=sysv", "-mno-80387", "-mno-mmx", "-mno-sse", "-mno-sse2", "-mno-red-zone", "-mcmodel=kernel" },
            ld_flags = { "-melf_x86_64" }
        },
        aarch64 = {
            c_flags = { "-mcpu=generic", "-march=armv8-a+nofp+nosimd", "-mgeneral-regs-only" },
            ld_flags = { "-maarch64elf"}
        },
        riscv64 = {
            c_flags = { "-march=rv64imac_zicsr_zifencei", "-mabi=lp64", "-mno-relax" },
            ld_flags = { "-m elf64lriscv", "--no-relax" }
        },
        loongarch64 = {
            c_flags = { "-march=loongarch64", "-mabi=lp64s", "-mfpu=none", "-msimd=none" },
            ld_flags = { "-melf64loongarch" }
        }
    }

    for _, flag in ipairs(arch_flags[build_info.target_architecture].c_flags) do
        table.insert(kernel_module.info.c_flags, flag)
    end

    for _, flag in ipairs(arch_flags[build_info.target_architecture].ld_flags) do
        table.insert(kernel_module.info.ld_flags, flag)
    end
    
    -- print("Built kernel module:", kernel_module.name)
    -- print(tbl_tostring(kernel_module, 0))

    return kernel_module
end