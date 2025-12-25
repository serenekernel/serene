
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
    local ovmf_module = {
        name = "ovmf",
        module_type = "custom",
        info = {
            commands = {
                "mkdir -p deps",
                "curl -L https://github.com/osdev0/edk2-ovmf-nightly/releases/latest/download/edk2-ovmf.tar.gz | gunzip | tar -C deps -xf -"
            },
            run_mode = "only_once",
        }
    }

    print("Built omvf module:", ovmf_module.name)
    print(tbl_tostring(ovmf_module, 0))

    return ovmf_module
end
