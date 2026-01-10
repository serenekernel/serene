#![no_std]
#![no_main]
use core::arch::asm;
use core::fmt;
use core::panic::PanicInfo;
use lazy_static::lazy_static;
use spin::Mutex;
use x86_64::instructions::port::Port;

#[inline(always)]
#[doc(hidden)]
pub fn raw_syscall(a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> usize {
    let ret: usize;

    unsafe {
        asm!(
            "syscall",
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8")  a4,
            in("r9")  a5,
            lateout("rax") ret,
            lateout("r15") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    ret
}

const SYS_EXIT: usize = 1;
const SYS_CAP_PORT_GRANT: usize = 32;

#[repr(isize)]
#[derive(Debug, Copy, Clone)]
enum SyscallError {
    InvalidArgument = -1,
    InvalidSyscallNumber = -2,
}

#[inline(always)]
#[doc(hidden)]
fn decode_ret(ret: usize) -> Result<usize, SyscallError> {
    let v = ret as isize;
    if v < 0 {
        Err(unsafe { core::mem::transmute(v) })
    } else {
        Ok(ret)
    }
}

pub fn sys_exit(code: usize) -> ! {
    let _ = raw_syscall(SYS_EXIT, code, 0, 0, 0, 0);
    loop {}
}

pub fn sys_cap_port_grant(start_port: u16, number_of_ports: u16) -> Result<(), SyscallError> {
    let ret = raw_syscall(
        SYS_CAP_PORT_GRANT,
        start_port as usize,
        number_of_ports as usize,
        0,
        0,
        0,
    );
    decode_ret(ret).map(|_| ())
}

pub fn test() -> Result<(), SyscallError> {
    let ret = raw_syscall(12, 0, 0, 0, 0, 0);
    decode_ret(ret).map(|_| ())
}

pub struct DebugWriter;

impl DebugWriter {
    pub fn write_byte(&mut self, byte: u8) {
        unsafe {
            Port::new(0xe9).write(byte);
        }
    }
    pub fn write_string(&mut self, s: &str) {
        for byte in s.bytes() {
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for DebugWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_string(s);
        Ok(())
    }
}

lazy_static! {
    pub static ref WRITER: Mutex<DebugWriter> = Mutex::new(DebugWriter {});
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    WRITER.lock().write_fmt(args).unwrap();
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => (_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => (print!("\n"));
    ($($arg:tt)*) => (print!("{}\n", format_args!($($arg)*)));
}

fn pci_read_config(bus: u8, slot: u8, func: u8, offset: u8) -> u32 {
    let address: u32 = (1 << 31)
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((func as u32) << 8)
        | ((offset as u32) & 0xfc);

    unsafe {
        let mut port_address = Port::new(0xcf8);
        let mut port_data = Port::new(0xcfc);
        port_address.write(address);
        port_data.read()
    }
}

struct PciDevice {
    bus: u8,
    slot: u8,
    function: u8,
    vendor_id: u16,
    device_id: u16,
    header_type: u8,
    class_code: u8,
    subclass: u8,
    prog_if: u8,

    secondary_bus: Option<u8>,
}

impl PciDevice {
    pub fn new(bus: u8, slot: u8, function: u8) -> Self {
        let val = pci_read_config(bus, slot, function, 0);
        let vendor_id = (val & 0xffff) as u16;
        let device_id = ((val >> 16) & 0xffff) as u16;

        let val = pci_read_config(bus, slot, function, 8);
        let class_code = ((val >> 24) & 0xff) as u8;
        let subclass = ((val >> 16) & 0xff) as u8;
        let prog_if = ((val >> 8) & 0xff) as u8;

        let val = pci_read_config(bus, slot, function, 12);
        let header_type = ((val >> 16) & 0xff) as u8;
        let secondary_bus;
        if class_code == 0x6 && subclass == 0x4 {
            let val = pci_read_config(bus, slot, function, 24);
            secondary_bus = Some(((val >> 8) & 0xff) as u8);
        } else {
            secondary_bus = None;
        }

        PciDevice {
            bus,
            slot,
            function,
            vendor_id,
            device_id,
            header_type,
            class_code,
            subclass,
            prog_if,
            secondary_bus,
        }
    }

    pub fn exists(bus: u8, slot: u8, function: u8) -> bool {
        let val = pci_read_config(bus, slot, function, 0);
        let vendor_id = (val & 0xffff) as u16;
        vendor_id != 0xFFFF
    }
}

fn pci_check_function(bus: u8, device_num: u8, function: u8) {
    let device = PciDevice::new(bus, device_num, function);
    println!(
        "[pci] {}:{}.{} - {:04x}:{:04x} Class {:02x}:{:02x}",
        bus,
        device_num,
        function,
        device.vendor_id,
        device.device_id,
        device.class_code,
        device.subclass
    );
    if device.secondary_bus.is_some() {
        let secondary_bus = device.secondary_bus.unwrap();
        pci_scan_bus(secondary_bus);
    }
}

fn pci_check_device(bus: u8, device_num: u8) {
    if !PciDevice::exists(bus, device_num, 0) {
        return;
    }

    pci_check_function(bus, device_num, 0);
    let device = PciDevice::new(bus, device_num, 0);
    if (device.header_type & 0x80) != 0 {
        // It's a multi-function device, so check remaining functions
        for function in 1..8 {
            if PciDevice::exists(bus, device_num, function) {
                pci_check_function(bus, device_num, function);
            }
        }
    }
}

fn pci_scan_bus(bus: u8) {
    for device in 0..32 {
        pci_check_device(bus, device);
    }
}

fn pci_scan() {
    let device = PciDevice::new(0, 0, 0);
    if (device.header_type & 0x80) == 0 {
        pci_scan_bus(0);
    } else {
        for function in 0..8 {
            if !PciDevice::exists(0, 0, function) {
                break;
            }
            pci_scan_bus(function);
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sys_cap_port_grant(0xe9, 1).expect("sys_cap_port_grant failed");
    sys_cap_port_grant(0xcf8, 4).expect("sys_cap_port_grant failed");
    sys_cap_port_grant(0xcfc, 4).expect("sys_cap_port_grant failed");
    println!("Hello world!");
    pci_scan();
    sys_exit(0);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("panic: {}", info);
    sys_exit(1);
}
