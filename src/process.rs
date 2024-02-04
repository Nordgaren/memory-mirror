use pe_util::PE;
use std::ffi::{c_void, CStr};
use std::fmt;
use std::io::{Error, ErrorKind};
use std::mem::size_of;
use std::ops::Range;

use crate::windows::api::{CloseHandle, CreateToolhelp32Snapshot, GetLastError, Module32First, Module32Next, OpenProcess, OpenThread, ReadProcessMemory, ResumeThread, SuspendThread, Thread32First, Thread32Next, VirtualQueryEx};
use crate::windows::consts::{
    INVALID_HANDLE_VALUE, MEM_FREE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, TH32CS_SNAPMODULE,
    TH32CS_SNAPTHREAD, THREAD_SUSPEND_RESUME,
};
use crate::windows::structs::{MEMORY_BASIC_INFORMATION, MODULEENTRY32, THREADENTRY32};
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

pub(crate) fn open_process(process: u32) -> std::io::Result<usize> {
    unsafe {
        let process_id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process);

        if process_id == INVALID_HANDLE_VALUE {
            let last_error = GetLastError();
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open process {process}. Invalid handle: {process_id}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(process_id)
    }
}

pub(crate) fn open_thread(access: u32, inherit: bool, thread: u32) -> std::io::Result<usize> {
    unsafe {
        let thread_id = OpenThread(access, inherit, thread);

        if thread_id == 0 {
            let last_error = GetLastError();
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open process {thread}. Invalid handle: {thread_id}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(thread_id)
    }
}

pub(crate) fn snapshot_process(process: u32) -> std::io::Result<usize> {
    unsafe {
        let snapshot_handle =
            CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, process);

        if snapshot_handle == INVALID_HANDLE_VALUE {
            let last_error = GetLastError();
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open snapshot for process {process}. Invalid handle: {snapshot_handle}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(snapshot_handle)
    }
}

pub(crate) unsafe fn freeze_process(snapshot: usize, process: u32) -> Vec<usize> {
    let mut thread_entry = THREADENTRY32::default();

    if !Thread32First(snapshot, &mut thread_entry) {
        panic!("Could not get first thread entry");
    }

    let mut handles = vec![];
    loop {
        if thread_entry.th32OwnerProcessID == process {
            let thread_handle =
                open_thread(THREAD_SUSPEND_RESUME, false, thread_entry.th32ThreadID);

            if let Ok(handle) = thread_handle {
                handles.push(handle);
                SuspendThread(handle);
            }
        }

        if !Thread32Next(snapshot, &mut thread_entry) {
            break;
        }
    }
    handles
}

pub(crate) unsafe fn resume_threads(threads: Vec<usize>) {
    for thread in threads.into_iter() {
        ResumeThread(thread);
        CloseHandle(thread);
    }
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

pub(crate) unsafe fn enumerate_memory_regions(process: usize) -> Vec<MemoryRegion> {
    let mut current_address = std::ptr::null::<c_void>();
    let mut current_entry = MEMORY_BASIC_INFORMATION::default();
    let mut results = vec![];

    loop {
        VirtualQueryEx(
            process,
            current_address,
            &mut current_entry,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        let base_address = current_entry.BaseAddress;
        let next_address = (base_address + current_entry.RegionSize) as *const c_void;

        if current_entry.State != MEM_FREE {
            results.push(MemoryRegion {
                state: current_entry.State,
                range: Range {
                    start: current_entry.BaseAddress,
                    end: current_entry.BaseAddress + current_entry.RegionSize,
                },
            });
        }

        // This will cause infinite loops when `current_address` gets back into a `None` state.
        if current_address == next_address {
            break;
        }

        current_address = next_address;
    }

    results
}

pub(crate) unsafe fn read_memory(process: usize, range: &Range<usize>) -> Option<Vec<u8>> {
    let size = range.end - range.start;
    let mut buffer = vec![0; size];
    let mut bytes_read = 0;

    let success = ReadProcessMemory(
        process,
        range.start,
        buffer.as_mut_ptr(),
        size,
        &mut bytes_read,
    );

    if success {
        Some(buffer)
    } else {
        None
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
