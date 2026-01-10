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
    local arch = build_info.target_architecture or "x86_64"
    local xorriso_command = {
        x86_64 =
            "xorriso -as mkisofs -R -r -J -b boot/limine/limine-bios-cd.bin -no-emul-boot -boot-load-size 4 -boot-info-table -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root -o build/output-" ..
            arch .. ".iso",
        aarch64 =
            "xorriso -as mkisofs -R -r -J -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root -o build/output-" ..
            arch .. ".iso",
        loongarch64 =
            "xorriso -as mkisofs -R -r -J -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root -o build/output-" ..
            arch .. ".iso",
        riscv64 =
            "xorriso -as mkisofs -R -r -J -hfsplus -apm-block-size 2048 --efi-boot boot/limine/limine-uefi-cd.bin -efi-boot-part --efi-boot-image --protective-msdos-label iso_root -o build/output-" ..
            arch .. ".iso"
    }
    local module = {
        name = "make_iso",
        module_type = "custom",
        depends_on = { "build_modules/kernel.lua" },
        info = {
            commands = {
                "rm -rf iso_root",
                "mkdir -p iso_root/boot",
                "cp -v build/kernel-" .. arch .. " iso_root/boot/kernel",
                "cp -v boot_mods/test iso_root/boot/test.elf",
                "mkdir -p iso_root/boot/limine",
                "cp -v limine.conf iso_root/boot/limine/",
                "mkdir -p iso_root/EFI/BOOT",
                "cp -v deps/limine/limine-bios.sys deps/limine/limine-bios-cd.bin deps/limine/limine-uefi-cd.bin iso_root/boot/limine/",
                "cp -v deps/limine/BOOTX64.EFI iso_root/EFI/BOOT/",
                "cp -v deps/limine/BOOTAA64.EFI iso_root/EFI/BOOT/",
                "cp -v deps/limine/BOOTLOONGARCH64.EFI iso_root/EFI/BOOT/",
                "cp -v deps/limine/BOOTRISCV64.EFI iso_root/EFI/BOOT/",
                xorriso_command[arch],
                "./deps/limine/limine bios-install build/output-" .. arch .. ".iso",
                "rm -rf iso_root"
            },
            run_mode = "rerun",
        }
    }



    print("Built omvf module:", module.name)
    print(tbl_tostring(module, 0))

    return module
end
