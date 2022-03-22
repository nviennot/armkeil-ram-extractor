use bytes::{Bytes, Buf};
use unicorn_engine::{Unicorn, RegisterARM};
use unicorn_engine::unicorn_const::{Arch, Mode, Permission, HookType};

use std::io::prelude::*;
use std::fs;
use std::sync::{Arc, Mutex};
use clap::Parser;
use clap::AppSettings;
use anyhow::{Result, Context};

use clap_num::maybe_hex;

/// Decompress .data section from a Keil compiled firmware
#[derive(Parser, Debug)]
#[clap(
    global_setting(AppSettings::DeriveDisplayOrder)
)]
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

    /// Base RAM address. Can be repeated.
    #[clap(long="base-ram", parse(try_from_str=maybe_hex))]
    base_rams: Vec<u32>,

    /// Initial PC address. Address should be an odd number to be in thumb mode.
    #[clap(long, parse(try_from_str=maybe_hex))]
    start_addr: Option<u32>,

    /// PC address at which to stop the emulation.
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

fn _find_last_non_zero_byte_idx(buf: &[u8]) -> usize {
    let mut result = 0;

    for (i, val) in buf.iter().enumerate() {
        if *val != 0 {
            result = i;
        }
    }

    result
}

fn dump_ram(emu: &Unicorn<()>, address: u32, size: usize, file_path: &str) {
    println!("Dumping RAM at addr=0x{:08x} size=0x{:08x} to {}", address, size, file_path);

    let content = emu.mem_read_as_vec(address.into(), size)
        .expect("Failed to read RAM");

    //let size = round_up(find_last_non_zero_byte_idx(&content)+1, 4);
    let mut content = &content[0..size];

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
    let mut base_rams = args.base_rams;
    if base_rams.is_empty() {
        base_rams.push(sp_addr & 0xFF00_0000);
    }

    let rom_size = round_up(firmware.len(), 4096);
    let ram_size = args.ram_size;

    println!("ROM segment: 0x{:08x}", base_rom);
    for base_ram in &base_rams {
        println!("RAM segment: 0x{:08x}", base_ram);
    }
    println!("Start addr:  0x{:08x}", start_addr);

    let mut emu = Unicorn::new(Arch::ARM, Mode::LITTLE_ENDIAN)
        .expect("failed to initialize Unicorn instance");

    emu.mem_map(base_rom.into(), rom_size as usize, Permission::ALL).expect("failed to map rom");
    for base_ram in &base_rams {
        emu.mem_map((*base_ram).into(), ram_size as usize, Permission::ALL).expect("failed to map ram");
    }

    emu.mem_write(base_rom.into(), &firmware).expect("failed to initialize rom segment");

    emu.reg_write(RegisterARM::SP, sp_addr.into()).expect("failed to set pc");

    let ram_sizes = base_rams.iter().map(|_| 0).collect::<Vec<_>>();

    let base_rams = Arc::new(base_rams);
    let ram_sizes = Arc::new(Mutex::new(ram_sizes));

    {
        let base_rams = Arc::clone(&base_rams);
        let ram_sizes = Arc::clone(&ram_sizes);
        emu.add_mem_hook(HookType::MEM_WRITE, 0, u64::MAX, move |_emu, _type, addr, size, _| {
            let addr = addr as u32;
            let size = size as u32;
            for (base, max_size) in base_rams.iter().zip(ram_sizes.lock().unwrap().iter_mut()) {
                if *base <= addr && addr <= *base + ram_size {
                    *max_size = (*max_size).max(addr+size-base);
                }
            }

            true
        }).expect("add_mem_hook failed");
    }

    emu.add_mem_hook(HookType::MEM_UNMAPPED, 0, u64::MAX, |emu, type_, addr, size, _| {
        let pc = emu.reg_read(RegisterARM::PC).expect("failed to get pc");
        println!("mem: {:?} inst_addr=0x{:08x} mem_addr=0x{:08x}, size = {}", type_, pc, addr, size);
        println!("Use `--stop-addr` to stop the execution, or add multiple ram blocks with --base-ram");
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

    if base_rams.len() == 1 {
        dump_ram(&emu, base_rams[0], ram_sizes.lock().unwrap()[0] as usize, &args.output);
    } else {
        for (base_ram, max_size) in base_rams.iter().zip(ram_sizes.lock().unwrap().iter()) {
            let filename = std::path::Path::new(&args.output);
            let base_filename = filename.file_stem().unwrap().to_string_lossy();
            let filename = format!("{}-{:08x}.bin", base_filename, *base_ram);
            dump_ram(&emu, *base_ram, *max_size as usize, &filename);
        }
    }

    Ok(())
}
