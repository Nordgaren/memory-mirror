#![windows_subsystem = "windows"]

use std::env;
use std::fs::File;
use std::io::Write;
use std::ops::Range;
use indicatif::ProgressIterator;
use pe_util::PE;
use crate::windows::api::GetLastError;
use crate::windows::consts::MEM_FREE;

mod process;
mod windows;

use crate::process::{
    get_dumpable_processes,
    enumerate_memory_regions,
    open_process,
    freeze_process,
    resume_threads,
    snapshot_process,
    enumerate_modules,
    MemoryRegion,
    ProcessModule,
    read_memory
};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        println!("Invocation was not correct. Example of proper invocation:");
        println!("./memory_mirror.exe <pid> <output path>");

        return;
    }

    let process_id = &args[1].parse::<u32>().expect("Process ID was not an int");
    let output_directory = &args[2];

    let process = get_dumpable_processes().into_iter()
        .find(|p| p.pid == *process_id)
        .expect("Could not find a process with specified ID");

    println!("Dumping process {}...", process);

    unsafe { dump(output_directory.clone(), process.pid); }
}

unsafe fn dump(path: String, pid: u32) {
    let snapshot = match snapshot_process(pid) {
        Ok(e) => e,
        Err(_) => {
            let e = GetLastError();
            println!("Error: {}", e);
            panic!("Last Error: {}", GetLastError())  ;
    },
    };
    let frozen_threads = freeze_process(snapshot, pid);

    let process_handle = open_process(pid).unwrap();

    let modules = enumerate_modules(process_handle, snapshot);
    let regions = enumerate_memory_regions(process_handle);

    let readable_regions = regions.into_iter()
        .filter(|m| m.state != MEM_FREE)
        .filter(|m| !modules.iter().any(|module| module.range.contains(&m.range.end)))
        .collect::<Vec<MemoryRegion>>();

    for module in modules {
        dump_module(
            path.clone(),
            process_handle,
            &module,
        )
    }

    for region in readable_regions.into_iter().progress() {
        dump_raw_region(
            path.clone(),
            process_handle,
            region,
        );
    }

    resume_threads(frozen_threads);
}

unsafe fn dump_module(
    path: String,
    process: usize,
    module: &ProcessModule,
) {
    if let Some(buffer) = read_memory(process, &module.range) {
        let buffer = patch_section_headers(buffer);
        let filename = build_filename(module.name.as_str(), &module.range);
        dump_buffer(format!("{}/{}", path, filename).as_str(), buffer);
    }
}

unsafe fn dump_raw_region(
    path: String,
    process: usize,
    region: MemoryRegion
) {
    if let Some(buffer) = read_memory(process, &region.range) {
        let filename = build_filename("UNK", &region.range);
        dump_buffer(format!("{}/{}", path, filename).as_str(), buffer);
    }
}

fn build_filename(label: &str, range: &Range<usize>) -> String {
    format!("{:x}-{:x}-{}.dump", range.start, range.end - range.start, label)
}

fn dump_buffer(path: &str, buffer: Vec<u8>) {
    let mut file = File::create(path).unwrap();
    file.write_all(buffer.as_slice()).unwrap();
}

unsafe fn patch_section_headers(buffer: Vec<u8>) -> Vec<u8> {
    let pe = PE::from_slice(&buffer[..]).expect("Could not read buffer as PE.");

    let sections = pe.section_headers_mut();
    for sections in sections {
        // Since we're dumping from memory we need to correct the PointerToRawData and SizeOfRawData
        // such that analysis tools can locate the sections again.
        sections.SizeOfRawData = sections.Misc.VirtualSize;
        sections.PointerToRawData = sections.VirtualAddress;
    }

    buffer
}