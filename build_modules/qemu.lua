function bind_sources(module, sources)
    for _, source in ipairs(sources) do
        table.insert(module.info.sources, source)
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

function run(build_info, run_info)
    local qemu_args = { 
        "-cdrom", "output-" .. (build_info.target_architecture or "x86_64") .. ".iso", 
        "-m", "2G", 
        "-M", "q35", 
        "-debugcon", "stdio", 
        "-d", "int,cpu_reset", 
        "-D", "qemu_err.log", 
        "--no-reboot", 
        "--no-shutdown" 
    }

    if run_info.flags.pause then
        table.insert(qemu_args, "-S")
    end

    if run_info.flags.uefi then
        table.insert(qemu_args, "-drive")
        table.insert(qemu_args, "if=pflash,format=raw,readonly=on,file=deps/edk2-ovmf/ovmf-code-" ..  (build_info.target_architecture or "x86_64") .. ".fd,readonly=on")
    end
    
    if run_info.flags.kvm then
        table.insert(qemu_args, "-accel")
        table.insert(qemu_args, "kvm")
        table.insert(qemu_args, "-cpu")
        table.insert(qemu_args, "host")
    elseif run_info.flags.hvf then
        table.insert(qemu_args, "-accel")
        table.insert(qemu_args, "hvf")
        table.insert(qemu_args, "-cpu")
        table.insert(qemu_args, "host")
    else
        table.insert(qemu_args, "-accel")
        table.insert(qemu_args, "tcg")
        table.insert(qemu_args, "-cpu")
        table.insert(qemu_args, "qemu64,x2apic=" .. (run_info.flags.x2apic and "on" or "off"))
    end

    return {
        run_type = "process",
        info = {
            executable = "qemu-system-" .. (build_info.target_architecture or "x86_64"),
            args = qemu_args
        }
    }
end

function build(build_info)
    local module = {
        name = "qemu",
        module_type = "run_target",
        depends_on = { 
        },
        info = {
            flags = {
                pause = { type = "bool", default = false },
                kvm = { type = "bool", default = false },
                tcg = { type = "bool", default = false },
                hvf = { type = "bool", default = false },
                x2apic = { type = "bool", default = true },
                uefi = { type = "bool", default = true },
            }
        }
    }


    -- print("Built module:", module.name)
    -- print(tbl_tostring(module, 0))
    return module
end