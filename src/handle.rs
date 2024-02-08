use crate::windows::api::{
    CloseHandle, CreateToolhelp32Snapshot, GetLastError, OpenProcess, OpenThread, ResumeThread,
    SuspendThread,
};
use crate::windows::consts::INVALID_HANDLE_VALUE;
use std::fmt::{Display, Formatter};
use std::io::{Error, ErrorKind};

pub(crate) struct FrozenThreadHandle(ThreadHandle);

impl FrozenThreadHandle {
    /// Opens a `ThreadHandle` to a thread via thread id and access parameters and suspends the thread, returning a `FrozenThreadHandle`
    /// if successful.
    pub fn new(access: u32, inherit: bool, thread: u32) -> std::io::Result<Self> {
        let handle = ThreadHandle::new(access, inherit, thread)?;
        Self::from_thread_handle(handle)
    }
    /// Calls `SuspendThread` on an existing `ThreadHandle`, returning a `FrozenThreadHandle` if successful.
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
    /// Returns the raw value of the handle as a usize.
    ///
    /// # Safety
    ///
    /// Calling this function give you the raw value of the handle. This value cannot be used by any other owned handle
    /// type, as when `FrozenThreadHandle` is dropped, it will call `ResumeThread`, as well as the underlying `ThreadHandle`
    /// will be dropped and call `CloseHandle`. If these functions have already been called on this handle, it could lead
    /// to undefined behaviour
    pub unsafe fn raw_value(&self) -> usize {
        self.0 .0
    }
    /// Resumes the thread and returns the underlying `ThreadHandle`.
    pub fn resume_thread(mut self) -> ThreadHandle {
        // SAFETY: the `resume_thread` as well as the `close_handle` function that `ThreadHandle` calls will both check
        // if the handle is not `INVALID_HANDLE_VALUE` before calling the windows api function it needs to call. This way
        // replacing the handle with `INVALID_HANDLE_VALUE` as defined by the windows api will not cause undefined behaviour.
        let handle = std::mem::replace(&mut self.0, ThreadHandle(INVALID_HANDLE_VALUE));
        unsafe { resume_thread(handle.0) };
        handle
    }
}

impl Drop for FrozenThreadHandle {
    fn drop(&mut self) {
        unsafe { resume_thread(self.raw_value()) };
    }
}

impl Display for FrozenThreadHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { self.raw_value() })
    }
}

pub(crate) struct ThreadHandle(usize);

impl ThreadHandle {
    /// Opens a `ThreadHandle` to a thread via thread id and access parameters, returning a `ThreadHandle` if successful.
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

        Ok(Self(handle))
    }
    /// Returns the raw value of the handle as a usize.
    ///
    /// # Safety
    ///
    /// Calling this function give you the raw value of the handle. This value cannot be used by any other owned handle
    /// type, as when `ThreadHandle` is dropped, it will call `CloseHandle`. If `CloseHandle` has already been called
    /// on this handle, it could lead to undefined behaviour
    #[allow(unused)]
    pub unsafe fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        unsafe { close_handle(self.raw_value()) }
    }
}

impl Display for ThreadHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { self.raw_value() })
    }
}

pub(crate) struct ProcessHandle(usize);

impl ProcessHandle {
    /// Opens a `ProcessHandle` to a thread via process id and access parameters, returning a `ProcessHandle` if successful.
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
    /// Returns the raw value of the handle as a usize.
    ///
    /// # Safety
    ///
    /// Calling this function gives you the raw value of the handle. This value cannot be used by any other owned handle
    /// type, as when `ProcessHandle` is dropped, it will call `CloseHandle`. If `CloseHandle` has already been called
    /// on this handle, it could lead to undefined behaviour
    pub unsafe fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { close_handle(self.raw_value()) }
    }
}

impl Display for ProcessHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { self.raw_value() })
    }
}

pub(crate) struct SnapshotHandle(usize);

impl SnapshotHandle {
    /// Opens a `SnapshotHandle` to a thread via process id and access parameters, returning a `SnapshotHandle` if successful.
    pub(crate) fn new(flags: u32, process: u32) -> std::io::Result<Self> {
        let handle = unsafe { CreateToolhelp32Snapshot(flags, process) };

        if handle == INVALID_HANDLE_VALUE {
            let last_error = unsafe { GetLastError() };
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!("Could not open snapshot for process {process}. Invalid handle: {handle}. LastError: 0x{last_error:X}"),
            ));
        }

        Ok(Self(handle))
    }
    /// Returns the raw value of the handle as a usize.
    ///
    /// # Safety
    ///
    /// Calling this function give you the raw value of the handle. This value cannot be used by any other owned handle
    /// type, as when `SnapshotHandle` is dropped, it will call `CloseHandle`. If `CloseHandle` has already been called
    /// on this handle, it could lead to undefined behaviour
    pub unsafe fn raw_value(&self) -> usize {
        self.0
    }
}

impl Drop for SnapshotHandle {
    fn drop(&mut self) {
        unsafe { close_handle(self.raw_value()) }
    }
}

impl Display for SnapshotHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", unsafe { self.raw_value() })
    }
}
/// Checks if the handle is not `INVALID_HANDLE_VALUE` and then calls `ResumeThread`
///
/// # Safety
///
/// This function must only be called on a thread handle that is suspended.
#[inline(always)]
unsafe fn resume_thread(handle: usize) {
    unsafe {
        if handle != INVALID_HANDLE_VALUE && ResumeThread(handle) == u32::MAX {
            println!(
                "Thread handle did not resume successfully: {handle} 0x{:X}",
                GetLastError()
            );
        }
    }
}
/// Checks if the handle is not `INVALID_HANDLE_VALUE` and then calls `CloseHandle`
///
/// # Safety
///
/// This function must only be called on a valid handle. Calling this function on a handle that has been closed is undefined
/// behaviour.
#[inline(always)]
unsafe fn close_handle(handle: usize) {
    unsafe {
        if handle != INVALID_HANDLE_VALUE && !CloseHandle(handle) {
            println!(
                "Handle did not close successfully: {handle} 0x{:X}",
                GetLastError()
            );
        }
    }
}
