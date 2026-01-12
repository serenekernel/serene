local opt_arch = fab.option("arch", { "x86_64" }) or "x86_64"
local opt_build_type = fab.option("buildtype", { "debug", "release" }) or "debug"

local kernel_sources = sources(fab.glob("kernel/src/**/*.c", "!kernel/src/arch/**"))
table.extend(kernel_sources, sources(fab.glob(path("kernel/src/arch", opt_arch, "**/*.c"))))

if opt_arch == "x86_64" then
    table.extend(kernel_sources, sources(fab.glob("kernel/src/arch/x86_64/**/*.asm")))
end

local c = require("lang_c")
local asm = require("lang_nasm")
local linker = require("ld")

local clang = c.get_clang()
assert(clang ~= nil, "No clang compiler found")

local nasm = asm.get_nasm()
assert(nasm ~= nil, "No nasm found")

local ld = linker.get_linker("ld.lld")
assert(ld ~= nil, "No ld.lld found")

local include_dirs = {
    c.include_dir(path("kernel/include/arch_dep/", opt_arch)),
    c.include_dir("kernel/include"),
    c.include_dir("kernel/include/lib")
}

local c_flags = {
    "-std=gnu23",
    "-ffreestanding",
    "-nostdinc",

    "-fno-stack-protector",
    "-fno-stack-check",
    "-fno-strict-aliasing",

    "-Wimplicit-fallthrough",
    "-Wmissing-field-initializers",
    
    "-fdiagnostics-color=always",
    "-DUACPI_BAREBONES_MODE",
    "-DLIMINE_API_REVISION=4"
}

if opt_build_type == "release" then
    table.extend(c_flags, {
        "-O3",
        "-flto",
    })
end

if opt_build_type == "debug" then
    table.extend(c_flags, {
        "-O2",
        "-g",
        -- "-fsanitize=undefined",
        "-fno-lto",
        "-fno-omit-frame-pointer",
    })
end


local freestanding_c_headers = fab.git(
    "freestanding-c-headers",
    "https://github.com/osdev0/freestnd-c-hdrs.git",
    "4039f438fb1dc1064d8e98f70e1cf122f91b763b"
)

local cc_runtime = fab.git(
    "cc-runtime",
    "https://github.com/osdev0/cc-runtime.git",
    "dae79833b57a01b9fd3e359ee31def69f5ae899b"
)

local limine_protocol = fab.git(
    "limine_protocol",
    "https://codeberg.org/Limine/limine-protocol.git",
    "trunk"
)

local uacpi = fab.git(
    "uacpi",
    "https://github.com/uACPI/uACPI.git",
    "3.2.0"
)

local flanterm = fab.git(
    "flanterm",
    "https://codeberg.org/Mintsuki/Flanterm.git",
    "trunk"
)

table.insert(include_dirs, c.include_dir(path(fab.build_dir(), uacpi.path, "include")))
table.insert(include_dirs, c.include_dir(path(fab.build_dir(), limine_protocol.path, "include")))
table.insert(include_dirs, c.include_dir(path(fab.build_dir(), flanterm.path, "src")))

local external_sources = {}
table.extend(external_sources, sources(fab.glob("source/*.c", { relative_to = path(fab.build_dir(), uacpi.path) })))
table.extend(external_sources, sources(fab.glob("src/*.c", { relative_to = path(fab.build_dir(), flanterm.path) })))

if opt_arch == "x86_64" then
    -- --- Includes
    table.insert(include_dirs, c.include_dir(path(fab.build_dir(), freestanding_c_headers.path, "x86_64/include")))

    -- -- Flags
    table.extend(c_flags, {
        "--target=x86_64-none-elf",
        "-mno-red-zone",
        "-mgeneral-regs-only",
        "-mabi=sysv",
        "-mcmodel=kernel",
        "-D__ARCH_X86_64__"
    })

    if opt_build_type == "debug" then
        table.insert(c_flags, "-fno-sanitize=alignment")
    end

    local nasm_flags = { "-f", "elf64", "-Werror" }
    local kernel_flags = {}
    table.extend(kernel_flags, c_flags)
    table.extend(kernel_flags, {
        "-Wall",
        "-Wextra",
        "-Wvla",
        "-Werror"
    })
    
    local external_objects = generate(external_sources, {
        c = function(sources) return clang:generate(sources, c_flags, include_dirs) end
    })

    local objects = generate(kernel_sources, {
        asm = function(sources) return nasm:generate(sources, nasm_flags) end,
        c = function(sources) return clang:generate(sources, c_flags, include_dirs) end
    })

    table.extend(objects, external_objects)

    local kernel = ld:link("kernel.elf", objects, {
        "-T" .. fab.path_rel("linker-scripts/x86_64.lds"),
        "-znoexecstack"
    })

    -- kernel("kernel.elf")
end
