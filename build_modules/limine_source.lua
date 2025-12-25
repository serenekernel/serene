
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
    local HOST_CC = "cc"
    local HOST_CFLAGS = "-g -O2 -pipe"
    local HOST_CPPFLAGS = ""
    local HOST_LDFLAGS = ""
    local HOST_LIBS = ""
    
    local configuration_string = "CC=\"" .. HOST_CC .. "\" CFLAGS=\"" .. HOST_CFLAGS .. "\" CPPFLAGS=\"" .. HOST_CPPFLAGS .. "\" LDFLAGS=\"" .. HOST_LDFLAGS .. "\" LIBS=\"" .. HOST_LIBS .. "\""
    local module = {
        name = "limine",
        module_type = "custom",
        info = {
            commands = {
                "cd deps/limine",
                "./bootstrap",
                configuration_string .. " ./configure --enable-bios-cd --enable-uefi-cd --enable-uefi-x86_64 --enable-uefi-aarch64 --enable-uefi-loongarch64 --enable-uefi-riscv64",
                "make -j8 " .. configuration_string
            },
            run_mode = "only_once",
        }
    }

    print("Built omvf module:", module.name)
    print(tbl_tostring(module, 0))

    return module
end
