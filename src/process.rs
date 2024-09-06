use std::ffi::{c_void, CStr};
use std::fs::File;
use std::io::{Error, ErrorKind, Write};
use std::mem::size_of;
use std::ops::Range;
use std::{fmt, fs};

use crate::handle::{FrozenThreadHandle, ProcessHandle, SnapshotHandle};
use crate::patch_section_headers;
use crate::windows::api::{
    GetLastError, GetThreadContext, Module32First, Module32Next, ReadProcessMemory, Thread32First,
    Thread32Next, VirtualQueryEx,
};
use crate::windows::consts::{
    CONTEXT_ALL, ERROR_INVALID_PARAMETER, MEM_FREE, THREAD_GET_CONTEXT, THREAD_SUSPEND_RESUME,
};
use crate::windows::structs::{CONTEXT, MEMORY_BASIC_INFORMATION, MODULEENTRY32, THREADENTRY32};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};

/// Retrieves a list of running process that we can dump
pub(crate) fn get_dumpable_processes() -> Vec<DumpableProcess> {
    let mut system = System::new();
    system.refresh_processes();

    let mut processes = system
        .processes()
        .iter()
        .map(|x| DumpableProcess {
            pid: x.0.as_u32(),
            name: x.1.name().to_string(),
        })
        .collect::<Vec<DumpableProcess>>();

    // Sort it backwards
    processes.sort_by(|a, b| b.pid.partial_cmp(&a.pid).unwrap());

    processes
}

#[derive(Debug, Clone)]
pub(crate) struct DumpableProcess {
    pub pid: u32,
    pub name: String,
}

impl fmt::Display for DumpableProcess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.pid)
    }
}

pub(crate) fn freeze_process(
    snapshot: &SnapshotHandle,
    pid: u32,
) -> std::io::Result<Vec<FrozenThreadInfo>> {
    let snapshot = unsafe { snapshot.raw_value() };
    let mut entry = THREADENTRY32::default();
    unsafe {
        if !Thread32First(snapshot, &mut entry) {
            return Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Could not get first thread entry. GetLastError: 0x{:X}",
                    GetLastError()
                ),
            ));
        }
    }

    let mut handles = vec![];
    loop {
        if entry.th32OwnerProcessID == pid {
            let handle = FrozenThreadHandle::new(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,
                false,
                entry.th32ThreadID,
            )?;

            handles.push(FrozenThreadInfo { handle, entry });
        }

        if unsafe { !Thread32Next(snapshot, &mut entry) } {
            break;
        }
    }
    Ok(handles)
}

pub(crate) fn enumerate_modules(
    snapshot: &SnapshotHandle,
) -> std::io::Result<Vec<ProcessModule>> {
    let snapshot = unsafe { snapshot.raw_value() };
    let mut current_entry = MODULEENTRY32::default();

    unsafe {
        if !Module32First(snapshot, &mut current_entry) {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                format!(
                    "Could not get first module entry. GetLastError: 0x{:X}",
                    GetLastError()
                ),
            ));
        }
    }

    let mut results = vec![];
    loop {
        let mut name = CStr::from_bytes_until_nul(&current_entry.szModule)
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?
            .to_str()
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e.to_string()))?
            .to_string();

        if name.is_empty() {
            name.push_str("UNK-MODULE")
        }

        let process_module = ProcessModule {
            name,
            range: Range {
                start: current_entry.modBaseAddr,
                end: current_entry.modBaseAddr + current_entry.modBaseSize as usize,
            },
        };

        // grab the size of the PE in memory, and set the range end to that.
        // let buffer = read_memory(process, &process_module.range)?;
        // let pe = unsafe { PE::from_slice_assume_mapped(&buffer[..], true) };
        // process_module.range.end =
        //     current_entry.hModule + pe.nt_headers().optional_header().size_of_image() as usize;

        results.push(process_module);

        unsafe {
            if !Module32Next(snapshot, &mut current_entry) {
                break;
            }
        }
    }

    Ok(results)
}

pub(crate) fn enumerate_memory_regions(process: &ProcessHandle) -> Vec<MemoryRegion> {
    let process = unsafe { process.raw_value() };
    let mut current_address = std::ptr::null::<c_void>();
    let mut current_entry = MEMORY_BASIC_INFORMATION::default();
    let mut results = vec![];

    loop {
        let result = unsafe {
            VirtualQueryEx(
                process,
                current_address,
                &mut current_entry,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };

        if result == 0 {
            // If lpAddress (current_address) specifies an address above the highest memory address accessible to the process,
            // the function fails with ERROR_INVALID_PARAMETER.
            let err = unsafe { GetLastError() };
            if err != ERROR_INVALID_PARAMETER {
                println!("VirtualQueryEx failed. GetLastError: 0x{err:X}");
                return results;
            }
        }

        let base_address = current_entry.BaseAddress;
        let next_address = (base_address + current_entry.RegionSize) as *const c_void;

        // This will cause infinite loops when `current_address` gets back into a `None` state.
        if current_address == next_address {
            break;
        }

        if current_entry.State != MEM_FREE {
            results.push(MemoryRegion {
                state: current_entry.State,
                range: Range {
                    start: current_entry.BaseAddress,
                    end: current_entry.BaseAddress + current_entry.RegionSize,
                },
            });
        }

        current_address = next_address;
    }

    results
}

pub(crate) fn read_memory(
    process: &ProcessHandle,
    range: &Range<usize>,
) -> std::io::Result<Vec<u8>> {
    let size = range.end - range.start;
    let mut buffer = vec![0; size];
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            process.raw_value(),
            range.start,
            buffer.as_mut_ptr(),
            size,
            &mut bytes_read,
        )
    };

    if success {
        return Ok(buffer);
    }

    Err(Error::new(
        ErrorKind::Other,
        format!(
            "Could not read memory for process {process} in range {range:X?} {}",
            unsafe { GetLastError() }
        ),
    ))
}

pub(crate) fn dump_module(
    path: &str,
    process: &ProcessHandle,
    module: &ProcessModule,
) -> std::io::Result<()> {
    let buffer = read_memory(process, &module.range)?;
    let buffer = patch_section_headers(buffer);
    let filename = build_filename(module.name.as_str(), &module.range);
    dump_buffer(&format!("{}/{}", path, filename), buffer)?;
    Ok(())
}

pub(crate) fn dump_raw_region(
    path: &str,
    process: &ProcessHandle,
    region: MemoryRegion,
) -> std::io::Result<()> {
    let buffer = read_memory(process, &region.range)?;
    let filename = build_filename("UNK", &region.range);
    dump_buffer(&format!("{}/{}", path, filename), buffer)?;
    Ok(())
}

fn build_filename(label: &str, range: &Range<usize>) -> String {
    format!(
        "{:x}-{:x}-{}.dump",
        range.start,
        range.end - range.start,
        label
    )
}

fn dump_buffer(path: &str, buffer: Vec<u8>) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(buffer.as_slice())?;
    Ok(())
}
pub fn dump_thread_context(path: &str, threads: &[FrozenThreadInfo]) {
    for thread in threads {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_ALL,
            ..Default::default()
        };
        unsafe {
            if !GetThreadContext(thread.handle.raw_value(), &mut context) {
                continue;
            }
        };

        let filepath = format!("{path}/{}_context.txt", thread.entry.th32ThreadID);
        if let Err(e) = fs::write(&filepath, format!("{context:#?}")) {
            println!("Could not write thread context to: {filepath}. Error: {e}")
        }
    }
}

#[derive(Debug)]
pub(crate) struct MemoryRegion {
    pub state: u32,
    pub range: Range<usize>,
}

#[derive(Debug)]
pub(crate) struct ProcessModule {
    pub name: String,
    pub range: Range<usize>,
}

pub(crate) struct FrozenThreadInfo {
    pub handle: FrozenThreadHandle,
    pub entry: THREADENTRY32,
}
