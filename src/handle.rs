use crate::windows::api::{
    CloseHandle, CreateToolhelp32Snapshot, GetLastError, OpenProcess, OpenThread, ResumeThread,
    SuspendThread,
};
use crate::windows::consts::INVALID_HANDLE_VALUE;
use std::io::{Error, ErrorKind};

pub(crate) struct FrozenThreadHandle(ThreadHandle);

impl FrozenThreadHandle {
    pub fn new(handle: ThreadHandle) -> std::io::Result<Self> {
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
        let handle = ThreadHandle::new(access, inherit, thread)?;
        Self::new(handle)
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
    pub fn new(access: u32, inherit: bool, thread_id: u32) -> std::io::Result<Self> {
        let handle = unsafe { OpenThread(access, inherit, thread_id) };

        // Return value
        // If the function succeeds, the return value is an open handle to the specified thread.
        // If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        if handle == 0 {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::Other,
                format!("Could not open process {thread_id}. Invalid handle: {handle}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(ThreadHandle(handle))
    }
    #[allow(unused)]
    pub fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        close_handle(self.0)
    }
}

pub(crate) struct ProcessHandle(usize);

impl ProcessHandle {
    pub fn new(access: u32, inherit: bool, process_id: u32) -> std::io::Result<Self> {
        let handle = unsafe { OpenProcess(access, inherit, process_id) };

        // Return value
        // If the function succeeds, the return value is an open handle to the specified process.
        // If the function fails, the return value is NULL. To get extended error information, call GetLastError.
        if handle == 0 {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open process {process_id}. Invalid handle: {handle}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(Self(handle))
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
    pub(crate) fn new(flags: u32, process: u32) -> std::io::Result<Self> {
        let handle = unsafe { CreateToolhelp32Snapshot(flags, process) };

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
