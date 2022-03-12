ARM Keil RAM Extractor
=======================

Usage:

```
Decompress .data section from a Keil compiled firmware

USAGE:
    armkeil-ram-extractor [OPTIONS] --firmware <FIRMWARE> --output <OUTPUT>

OPTIONS:
        --base-ram <BASE_RAM>        Base RAM address
        --base-rom <BASE_ROM>        Base ROM address
    -h, --help                       Print help information
    -o, --output <OUTPUT>            File where to write the RAM content
    -r, --rom <ROM>                  Firmware file
        --ram-size <RAM_SIZE>        RAM size [default: 1048576]
        --start-addr <START_ADDR>    Initial PC address. Don't forget to add 1 to be in thumb mode
        --stop-addr <STOP_ADDR>      PC address at which to stop the emulation. If not specified,
                                     will stop if executing at an address lower than the reset
                                     address

```

Example:

```
» cargo run -- --rom ./fw.bin --output ram.bin
    Finished dev [unoptimized + debuginfo] target(s) in 0.11s
     Running `target/debug/armkeil-ram-extractor --rom ./fw.bin --output ram.bin`
ROM segment: 0x00000000
RAM segment: 0x20000000
Start addr:  0x00000341
Stop addr:   0x00000288
Emulation finished
Dumping RAM at addr=0x20000000 size=5868 to ram.bin
```

License
-------

MIT License
