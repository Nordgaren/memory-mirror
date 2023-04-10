use std::env;
use std::fs::File;
use std::io::Write;
use std::mem::size_of;
use std::ops::Range;
use indicatif::ProgressIterator;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Memory::{MEM_FREE};
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::Diagnostics::Debug::{IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};

mod process;

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
    let snapshot = snapshot_process(pid).unwrap();
    let frozen_threads = freeze_process(snapshot, pid);

    let process_handle = open_process(pid).unwrap();

    let modules = enumerate_modules(snapshot);
    let regions = enumerate_memory_regions(process_handle);

    let readable_regions = regions.into_iter()
        .filter(|m| m.state != MEM_FREE)
        .collect::<Vec<MemoryRegion>>();

    for region in readable_regions.into_iter().progress() {
        let associated_module = modules.iter()
            .find(|m| m.range.contains(&region.range.start));

        match associated_module {
            Some(module) => dump_module_region(
                path.clone(),
                process_handle,
                module,
                region,
            ),
            None => dump_raw_region(
                path.clone(),
                process_handle,
                region,
            ),
        }
    }

    resume_threads(frozen_threads);
}

unsafe fn dump_module_region(
    path: String,
    process: HANDLE,
    module: &ProcessModule,
    region: MemoryRegion
) {
    if let Some(buffer) = read_memory(process, &region.range) {
        let buffer = patch_section_headers(buffer);
        let filename = build_filename(module.name.as_str(), &region.range);
        dump_buffer(format!("{}/{}", path, filename).as_str(), buffer);
    }
}

unsafe fn dump_raw_region(
    path: String,
    process: HANDLE,
    region: MemoryRegion
) {
    if let Some(buffer) = read_memory(process, &region.range) {
        let filename = build_filename("UNK", &region.range);
        dump_buffer(format!("{}/{}", path, filename).as_str(), buffer);
    }
}

fn build_filename(label: &str, range: &Range<isize>) -> String {
    format!("{:x}-{:x}-{}.dump", range.start, range.end - range.start, label)
}

fn dump_buffer(path: &str, buffer: Vec<u8>) {
    let mut file = File::create(path).unwrap();
    file.write_all(buffer.as_slice()).unwrap();
}

unsafe fn patch_section_headers(buffer: Vec<u8>) -> Vec<u8> {
    let buffer_ptr = buffer.as_ptr() as usize;

    // Figure out the offset in the buffer to the NT header
    let nt_header_offset = (*(buffer_ptr as *const IMAGE_DOS_HEADER)).e_lfanew as usize;

    // Read the NT header to figure out how sections we have and how much RVA's + sizes so we
    // can determine the offset to the section headers;
    let nt_header = *((buffer_ptr + nt_header_offset) as *const IMAGE_NT_HEADERS64);
    let section_count = nt_header.FileHeader.NumberOfSections;
    let rva_count = nt_header.OptionalHeader.NumberOfRvaAndSizes;

    // Locate the section headers. Rust's IMAGE_NT_HEADERS64 assumes a fixed 16 RVA's but this might
    // be different in reality so we take care of the situation where it's less by manually
    // adjusting the offset.
    let section_base = nt_header_offset
        + size_of::<IMAGE_NT_HEADERS64>()
        + ((rva_count - 16) * 8) as usize;

    let section_header_size = size_of::<IMAGE_SECTION_HEADER>();
    for i in 0..section_count {
        let section_header_offset = section_base + section_header_size * i as usize;
        let mut section_header = (buffer_ptr + section_header_offset) as *mut IMAGE_SECTION_HEADER;

        // Since we're dumping from memory we need to correct the PointerToRawData and SizeOfRawData
        // such that analysis tools can locate the sections again.
        (*section_header).SizeOfRawData = (*section_header).Misc.VirtualSize;
        (*section_header).PointerToRawData = (*section_header).VirtualAddress;
    }

    buffer
}