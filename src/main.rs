use std::fs::File;
use std::io::Seek;
use std::io::SeekFrom;
use binread::BinRead;
use binread::BinReaderExt;
use proc_maps::{get_process_maps, Pid};
use patternscan::scan;
use std::io::Cursor;
use std::io::Read;
use std::collections::HashMap;
use clap::Parser;


#[derive(BinRead)]
#[derive(Debug)]
#[allow(dead_code)]
struct Kcbh {
    type_kcbh: u8,
    frmt_kcbh: u8, 
    spare1_kcbh: u8,
    spare2_kcbh: u8,
    rdba_kcbh: u32,
    bas_kcbh: u32,
    wrp_kcbh: u16,
    seq_kcbh: u8,
    flg_kcbh: u8, 
    chkval_kcbh: u16,
    spare3_kcbh: u16
}

#[derive(BinRead)]
#[derive(Debug)]
struct Ktbbh {
    ktbbhtyp: u32,
    ktbbhsid: u32
}

#[allow(dead_code)]
#[derive(BinRead)]
struct Ids {
    #[br(count = 1_048_576)]
    rdba_objd: Vec<u8>,
}

/// Tool for finding oracle database blocks and blocks metadata in memory
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
	///Size of memory segment to scan
	#[clap(short, long)]
	memory_size: u64,

	///PID of the process to scan
	#[clap(short, long)]
	pid: u64,

	///DATA_OBJECT_ID of searched object
	#[clap(short, long)]
	objd: u32,
}

fn main() {
    let args = Args::parse();
    let block_size: u64 = 4096;
    let pid = args.pid;
    let objd = args.objd;
    let mem_size = args.memory_size;

    let mut scan_from: u64 = 0;
    let mut scan_to: u64 = block_size;

    let maps = get_process_maps(pid as Pid).unwrap();

    for map in maps {
        if (map.size() as u64) == mem_size {
            scan_from = map.start() as u64;
            scan_to   = scan_from + (map.size() as u64);
            println!("Found map at the begining {} and end {}", scan_from, scan_to);
            break;
        }
    }

    let fname = format!("/proc/{}/mem", pid);
    let mut f = File::open(fname).unwrap();

    let mut found_blocks: HashMap<u64, Kcbh> = HashMap::new();

    let mut position = scan_from;
    while position < scan_to {
        f.seek(SeekFrom::Start(position)).unwrap();
        let kcbh: Kcbh = f.read_ne().unwrap();
        let ktbbh: Ktbbh = f.read_ne().unwrap();
        if ktbbh.ktbbhtyp == 1 && ktbbh.ktbbhsid == objd && kcbh.type_kcbh == 6 {
            found_blocks.insert(position, kcbh);
        }
        position += block_size;
        print!("\rScanning for blocks: {} %", ((position-scan_from) as f64 / (scan_to-scan_from) as f64 * 100 as f64) as u8);
    }

    println!("\nNow preparing patterns for X$BH scan for {} found blocks", found_blocks.len());

    position = scan_from;
    let objd_b = objd.to_ne_bytes();

    while position < scan_to {
        f.seek(SeekFrom::Start(position)).unwrap();
        let mut buffer = [0; 1_048_576];
        f.read(&mut buffer).unwrap();
        for (block_position, kcbh) in &found_blocks {
            let rdba = kcbh.rdba_kcbh.to_ne_bytes();
            let pattern = format!("{:02x} {:02x} {:02x} {:02x} ? ? ? ? {:02x} {:02x} {:02x} {:02x}", rdba[0], rdba[1], rdba[2], rdba[3], objd_b[0], objd_b[1], objd_b[2], objd_b[3]);
            let positions = scan(Cursor::new(buffer), &pattern).unwrap();
            if positions.len() > 0 {
                println!("\nPosition of database block RDBA: {:x} is {}, bas_kcbh={}, XBH position is: {}", kcbh.rdba_kcbh, block_position, kcbh.bas_kcbh, positions[0] as u64 + position);
            }
        }
        position += 1_048_576;
        print!("\rScanned: {} %", ((position-scan_from) as f64 / (scan_to-scan_from) as f64 * 100 as f64) as u8);
    }
}
