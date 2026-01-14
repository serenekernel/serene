local opt_arch = fab.option("arch", { "x86_64", "aarch64" }) or "x86_64"
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
    c.include_dir(path("kernel/include/arch/", opt_arch)),
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

local flanterm = fab.git(
    "flanterm",
    "https://codeberg.org/Mintsuki/Flanterm.git",
    "trunk"
)

table.insert(include_dirs, c.include_dir(path(fab.build_dir(), limine_protocol.path, "include")))
table.insert(include_dirs, c.include_dir(path(fab.build_dir(), flanterm.path, "src")))
table.insert(include_dirs, c.include_dir(path(fab.build_dir(), freestanding_c_headers.path, opt_arch .. "/include")))

local flanterm_sources = {}
table.extend(flanterm_sources, sources(fab.glob("src/*.c", { relative_to = flanterm.path })))


if opt_arch == "x86_64" then
    -- Flags
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
elseif opt_arch == "aarch64" then
    -- Flags
    table.extend(c_flags, {
        "--target=aarch64-none-elf",
        "-D__ARCH_AARCH64__"
    })
end

local objects = {}
local flanterm_objects = generate(flanterm_sources, {
    c = function(sources) return clang:generate(sources, c_flags, include_dirs) end
})

table.extend(objects, flanterm_objects)

local kernel_flags = {}
table.extend(kernel_flags, c_flags)
table.extend(kernel_flags, {
    "-Wall",
    "-Wextra",
    "-Wvla",
    "-Werror"
})

local generators = {
    c = function(sources) return clang:generate(sources, kernel_flags, include_dirs) end
}

local linker_script

if opt_arch == "x86_64" then
    local nasm_flags = { "-f", "elf64", "-Werror" }

    generators.asm = function(sources) return nasm:generate(sources, nasm_flags) end

    linker_script = fab.def_source("linker-scripts/x86_64.lds")
elseif opt_arch == "aarch64" then
    linker_script = fab.def_source("linker-scripts/aarch64.lds")
end

table.extend(objects, generate(kernel_sources, generators))

local kernel = ld:link("kernel.elf", objects, {
    "-znoexecstack"
}, linker_script)

return {
    install = {
        ["kernel.elf"] = kernel
    }
}