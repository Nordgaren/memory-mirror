use std::fmt;
use std::ops::Range;
use std::mem::size_of;
use std::ffi::{c_void, CStr};

use windows::Win32::Foundation::HANDLE;
use sysinfo::{ProcessExt, Pid, System, SystemExt, PidExt};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_FREE, VIRTUAL_ALLOCATION_TYPE};
use windows::Win32::System::Threading::{OpenProcess, OpenThread, SuspendThread, ResumeThread, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, THREAD_SUSPEND_RESUME};
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next, TH32CS_SNAPMODULE, MODULEENTRY32, Module32First, Module32Next};

/// Retrieves a list of running process that we can dump
pub(crate) fn get_dumpable_processes() -> Vec<DumpableProcess> {
    let mut system = System::new();
    system.refresh_processes();

    let mut processes = system.processes()
        .iter()
        .map(|x| DumpableProcess { pid: x.0.as_u32(), name: x.1.name().to_string() })
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

pub(crate) unsafe fn open_process(process: u32) -> windows::core::Result<HANDLE> {
    OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        false,
        process,
    )
}

pub(crate) unsafe fn snapshot_process(process: u32) -> windows::core::Result<HANDLE> {
    CreateToolhelp32Snapshot(
        TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE,
        process,
    )
}

pub(crate) unsafe fn freeze_process(snapshot: HANDLE, process: u32) -> Vec<HANDLE> {
    let mut thread_entry = THREADENTRY32::default();
    thread_entry.dwSize = size_of::<THREADENTRY32>() as u32;

    if !Thread32First(snapshot, &mut thread_entry).as_bool() {
        panic!("Could not get first thread entry");
    }

    let mut handles = vec![];
    loop {
        if thread_entry.th32OwnerProcessID == process {
            let thread_handle = OpenThread(
                THREAD_SUSPEND_RESUME,
                false,
                thread_entry.th32ThreadID,
            );

            if let Ok(handle) = thread_handle {
                handles.push(handle);
                SuspendThread(handle);
            }
        }

        if !Thread32Next(snapshot, &mut thread_entry).as_bool() {
            break;
        }
    }
    handles
}

pub(crate) unsafe fn resume_threads(threads: Vec<HANDLE>) {
    for thread in threads.iter() {
        ResumeThread(*thread);
    }
}

pub(crate) unsafe fn enumerate_modules(snapshot: HANDLE) -> Vec<ProcessModule> {
    let mut current_entry = MODULEENTRY32::default();
    current_entry.dwSize = size_of::<MODULEENTRY32>() as u32;

    if !Module32First(snapshot, &mut current_entry).as_bool() {
        panic!("Could not get first module entry");
    }

    let mut results = vec![];
    loop {
        let module_name = CStr::from_bytes_until_nul(&current_entry.szModule)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        results.push(ProcessModule {
            name: module_name,
            range: Range {
                start: current_entry.hModule.0,
                end: current_entry.hModule.0 + current_entry.dwSize as isize,
            },
        });

        if !Module32Next(snapshot, &mut current_entry).as_bool() {
            break;
        }
    }

    results
}

pub(crate) unsafe fn enumerate_memory_regions(process: HANDLE) -> Vec<MemoryRegion> {
    let mut current_address = None as Option<*const c_void>;
    let mut current_entry = MEMORY_BASIC_INFORMATION::default();
    let mut results = vec![];

    loop {
        VirtualQueryEx(
            process,
            current_address,
            &mut current_entry,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        );

        let base_address = current_entry.BaseAddress as usize;
        let next_address = (base_address + current_entry.RegionSize) as *const c_void;

        if current_entry.State != MEM_FREE {
            results.push(MemoryRegion {
                state: current_entry.State,
                range: Range {
                    start: current_entry.BaseAddress as isize,
                    end: current_entry.BaseAddress as isize + current_entry.RegionSize as isize,
                }
            });
        }

        // This will cause infinite loops when `current_address` gets back into a `None` state.
        if current_address.map(|a| a == next_address).unwrap_or(false) {
            break;
        }

        current_address = Some(next_address);
    }

    results
}

pub(crate) unsafe fn read_memory(process: HANDLE, range: &Range<isize>) -> Option<Vec<u8>> {
    let size = (range.end - range.start) as usize;
    let buffer = vec![0 as u8; size];
    let mut bytes_read = 0;

    let success = ReadProcessMemory(
        process,
        range.start as *const c_void,
        buffer.as_ptr() as *mut c_void,
        size,
        Some(&mut bytes_read),
    );

    if success.as_bool() {
        Some(buffer)
    } else {
        None
    }
}

#[derive(Debug)]
pub(crate) struct MemoryRegion {
    pub state: VIRTUAL_ALLOCATION_TYPE,
    pub range: Range<isize>,
}

#[derive(Debug)]
pub(crate) struct ProcessModule {
    pub name: String,
    pub range: Range<isize>,
}