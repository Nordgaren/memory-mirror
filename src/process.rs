use pe_util::PE;
use std::ffi::{c_void, CStr};
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::ops::Range;
use std::{fmt, fs};

use crate::handle::FrozenThreadHandle;
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

pub(crate) fn freeze_process(snapshot: usize, pid: u32) -> std::io::Result<Vec<FrozenThreadInfo>> {
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

pub(crate) unsafe fn enumerate_modules(process: usize, snapshot: usize) -> Vec<ProcessModule> {
    let mut current_entry = MODULEENTRY32::default();

    if !Module32First(snapshot, &mut current_entry) {
        panic!("Could not get first module entry");
    }

    let mut results = vec![];
    loop {
        let mut name = CStr::from_bytes_until_nul(&current_entry.szModule)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        if name.is_empty() {
            name.push_str("UNK-MODULE")
        }

        let mut process_module = ProcessModule {
            name,
            range: Range {
                start: current_entry.hModule,
                end: current_entry.hModule + current_entry.dwSize as usize,
            },
        };

        // grab the size of the PE in memory, and set the range end to that.
        let buffer =
            read_memory(process, &process_module.range).expect("Could not read process memory.");
        let pe = PE::from_slice_assume_mapped(&buffer[..], true);
        process_module.range.end =
            current_entry.hModule + pe.nt_headers().optional_header().size_of_image() as usize;

        results.push(process_module);

        if !Module32Next(snapshot, &mut current_entry) {
            break;
        }
    }

    results
}

pub(crate) fn enumerate_memory_regions(process: usize) -> Vec<MemoryRegion> {
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
                println!("VirtualQueryEx failed. GetLastError: 0x{err:X}")
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

pub(crate) fn read_memory(process: usize, range: &Range<usize>) -> std::io::Result<Vec<u8>> {
    let size = range.end - range.start;
    let mut buffer = vec![0; size];
    let mut bytes_read = 0;

    let success = unsafe {
        ReadProcessMemory(
            process,
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

pub fn dump_thread_context(path: &str, threads: &[FrozenThreadInfo]) {
    for thread in threads {
        let mut context = CONTEXT { ContextFlags: CONTEXT_ALL, ..Default::default() };
        unsafe {
            if !GetThreadContext(thread.handle.raw_value(), &mut context) {
                continue;
            }
        };


        let filepath = format!("{path}/_{}_context.txt", thread.entry.th32ThreadID);
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
