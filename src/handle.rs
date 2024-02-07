use crate::windows::api::{
    CloseHandle, CreateToolhelp32Snapshot, GetLastError, OpenProcess, OpenThread, ResumeThread,
    SuspendThread,
};
use crate::windows::consts::{
    INVALID_HANDLE_VALUE, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ, TH32CS_SNAPMODULE,
    TH32CS_SNAPTHREAD,
};
use std::io::{Error, ErrorKind};

pub(crate) struct FrozenThreadHandle(ThreadHandle);

impl FrozenThreadHandle {
    pub fn from_thread_handle(handle: ThreadHandle) -> std::io::Result<Self> {
        unsafe {
            if SuspendThread(handle.0) == u32::MAX {
                return Err(Error::new(
                    ErrorKind::Other,
                    format!(
                        "Could not suspend thread {}. LastError: 0x{:X}",
                        handle.0,
                        GetLastError()
                    ),
                ));
            }
        }

        Ok(Self(handle))
    }
    pub fn from_thread_id(access: u32, inherit: bool, thread: u32) -> std::io::Result<Self> {
        let handle = ThreadHandle::from_thread_id(access, inherit, thread)?;
        Self::from_thread_handle(handle)
    }
    pub fn raw_value(&self) -> usize {
        self.0 .0
    }
}

impl Drop for FrozenThreadHandle {
    fn drop(&mut self) {
        resume_thread(self.raw_value());
    }
}

pub(crate) struct ThreadHandle(usize);

impl ThreadHandle {
    pub fn from_thread_id(access: u32, inherit: bool, thread: u32) -> std::io::Result<Self> {
        let thread_id = unsafe { OpenThread(access, inherit, thread) };

        if thread_id == 0 {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::Other,
                format!("Could not open process {thread}. Invalid handle: {thread_id}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(ThreadHandle(thread_id))
    }
    pub fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        close_handle(self.0)
    }
}

#[inline(always)]
fn resume_thread(handle: usize) {
    unsafe {
        if ResumeThread(handle) == u32::MAX {
            println!(
                "Thread handle did not resume successfully: {} 0x{:X}",
                handle,
                GetLastError()
            );
        }
    }
}

#[inline(always)]
fn close_handle(handle: usize) {
    unsafe {
        if !CloseHandle(handle) {
            println!(
                "Handle did not close successfully: {} 0x{:X}",
                handle,
                GetLastError()
            );
        }
    }
}

pub(crate) struct ProcessHandle(usize);

impl ProcessHandle {
    pub fn from_pid(process: u32) -> std::io::Result<Self> {
        let process_id =
            unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process) };

        if process_id == INVALID_HANDLE_VALUE {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open process {process}. Invalid handle: {process_id}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(Self(process_id))
    }
    pub fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        close_handle(self.0)
    }
}

pub(crate) struct SnapshotHandle(usize);

impl SnapshotHandle {
    pub(crate) fn from_pid(process: u32) -> std::io::Result<Self> {
        let handle =
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD | TH32CS_SNAPMODULE, process) };

        if handle == INVALID_HANDLE_VALUE {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open snapshot for process {process}. Invalid handle: {handle}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(SnapshotHandle(handle))
    }
    pub fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        close_handle(self.0)
    }
}
