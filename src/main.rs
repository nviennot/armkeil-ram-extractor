use bytes::{Bytes, Buf};
use unicorn_engine::{Unicorn, RegisterARM};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, HookType};

use std::io::prelude::*;
use std::fs;
use clap::Parser;
use anyhow::{Result, Context};

use clap_num::maybe_hex;

/// Decompress .data section from a Keil compiled firmware
#[derive(Parser, Debug)]
struct Args {
    /// Firmware file
    #[clap(short, long)]
    rom: String,

    /// File where to write the RAM content
    #[clap(short, long)]
    output: String,

    /// Vector table offset. Useful when the firmware has a bootloader to skip
    #[clap(long, parse(try_from_str=maybe_hex), default_value_t=0)]
    skip: u32,

    /// Base ROM address
    #[clap(long, parse(try_from_str=maybe_hex))]
    base_rom: Option<u32>,

    /// Base RAM address
    #[clap(long, parse(try_from_str=maybe_hex))]
    base_ram: Option<u32>,

    /// Initial PC address. Don't forget to add 1 to be in thumb mode.
    #[clap(long, parse(try_from_str=maybe_hex))]
    start_addr: Option<u32>,

    /// PC address at which to stop the emulation. If not specified, will stop
    /// if executing at an address lower than the reset address.
    #[clap(long, parse(try_from_str=maybe_hex))]
    stop_addr: Option<u32>,

    /// RAM size
    #[clap(long, parse(try_from_str=maybe_hex), default_value_t=1*1024*1024)]
    ram_size: u32,
}

fn get_file_content(path: &str) -> Result<Vec<u8>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open {}", path))?;
    let mut content = vec![];
    file.read_to_end(&mut content)
        .with_context(|| format!("Failed to read {}", path))?;
    Ok(content)
}

fn round_up(n: usize, boundary: usize) -> usize {
    ((n + boundary - 1) / boundary) * boundary
}

fn find_last_non_zero_byte(buf: &[u8]) -> usize {
    let mut result = 0;

    for (i, val) in buf.iter().enumerate() {
        if *val != 0 {
            result = i;
        }
    }

    result
}

fn dump_ram(emu: &Unicorn<()>, address: u32, size: u32, file_path: &str) {
    let content = emu.mem_read_as_vec(address.into(), size as usize)
        .expect("Failed to read RAM");

    let size = round_up(find_last_non_zero_byte(&content), 4);
    let mut content = &content[0..size];

    println!("Dumping RAM at addr=0x{:08x} size=0x{:08x} to {}", address, size, file_path);

    let mut file = fs::File::create(&file_path).expect("Failed to create RAM file");
    file.write_all(&mut content).expect("Failed to write to RAM file");
}

fn main() -> Result<()> {
    let args = Args::parse();

    let firmware = get_file_content(&args.rom)?;

    let mut fw = Bytes::from(firmware.clone());
    fw.advance(args.skip as usize);
    let sp_addr = fw.get_u32_le();
    let reset_addr = fw.get_u32_le();

    // +4 because the first initialization routine is to init the CPU.
    // The second routine is what we are after.
    let start_addr = args.start_addr.unwrap_or(reset_addr + 4);
    let base_rom = args.base_rom.unwrap_or(reset_addr & 0xFF00_0000);
    let base_ram = args.base_ram.unwrap_or(sp_addr & 0xFF00_0000);

    let rom_size = round_up(firmware.len(), 4096);
    let ram_size = args.ram_size;

    println!("ROM segment: 0x{:08x}", base_rom);
    println!("RAM segment: 0x{:08x}", base_ram);
    println!("Start addr:  0x{:08x}", start_addr);

    let mut emu = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    emu.mem_map(base_rom.into(), rom_size as usize, Permission::ALL).expect("failed to map rom");
    emu.mem_map(base_ram.into(), ram_size as usize, Permission::ALL).expect("failed to map ram");

    emu.mem_write(base_rom.into(), &firmware).expect("failed to initialize rom segment");

    emu.reg_write(RegisterARM::SP, sp_addr.into()).expect("failed to set pc");

    emu.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX, |emu, type_, addr, size, _| {
        let pc = emu.reg_read(RegisterARM::PC).expect("failed to get pc");
        println!("mem: {:?} inst_addr=0x{:08x} mem_addr=0x{:08x}, size = {}", type_, pc, addr, size);
        false
    }).expect("add_mem_hook failed");

    emu.add_code_hook(0, u64::MAX, |_emu, _addr, _size| {
        // Removing the code hook breaks things for some reason. Whatever.
    }).expect("add_code_hook failed");

    let stop_addr = match args.stop_addr {
        Some(v) => { v as u64 },
        None => {
            emu.emu_start(start_addr.into(), u64::MAX, 0, 3)
                .expect("Failed to emulate the firmware");

            let pc = emu.reg_read(RegisterARM::PC).expect("failed to get pc");
            pc+4
        }
    };

    println!("Stop addr:   0x{:08x}", stop_addr);

    emu.emu_start(start_addr.into(), stop_addr, 0, 0)
        .expect("Failed to emulate the firmware");

    println!("Emulation finished");

    dump_ram(&emu, base_ram, ram_size, &args.output);

    Ok(())
}
