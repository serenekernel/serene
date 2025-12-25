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

function build(build_info)
    local module = {
        name = "limine-serenebuild-template",
        module_type = "project",
        depends_on = { 
            "build_modules/kernel.lua", 
            "build_modules/ovmf.lua", 
            "build_modules/limine.lua",
            "build_modules/make_iso.lua" 
        },
    }
    print("Built module:", module.name)
    print(tbl_tostring(module, 0))
    return module
end
