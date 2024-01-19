#![allow(non_snake_case)]

use crate::windows::structs::{THREADENTRY32, MEMORY_BASIC_INFORMATION, MODULEENTRY32};
use std::ffi::c_void;

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    pub fn CreateToolhelp32Snapshot(dwFlags: u32, th32ProcessID: u32) -> usize;
    pub fn GetLastError() -> u32;
    pub fn Module32First(hSnapshot: usize, lpee: *mut MODULEENTRY32) -> bool;
    pub fn Module32Next(hSnapshot: usize, lpee: *mut MODULEENTRY32) -> bool;
    pub fn OpenProcess(dwDesiredAccess: u32, bInheritHandle: bool, dwProcessId: u32) -> usize;
    pub fn OpenThread(dwDesiredAccess: u32, bInheritHandle: bool, dwThreadId: u32) -> usize;
    pub fn ReadProcessMemory(
        hProcess: usize,
        lpBaseAddress: usize,
        lpBuffer: *mut u8,
        nSize: usize,
        lpNumberOfBytesRead: &mut usize,
    ) -> bool;
    pub fn ResumeThread(hThread: usize) -> u32;
    pub fn SuspendThread(hThread: usize) -> u32;
    pub fn Thread32First(hSnapshot: usize, lpte: &mut THREADENTRY32) -> bool;
    pub fn Thread32Next(hSnapshot: usize, lpte: &mut THREADENTRY32) -> bool;
    pub fn VirtualQueryEx(
              hProcess: usize,
              lpAddress: *const c_void,
              lpBuffer: *mut MEMORY_BASIC_INFORMATION,
              dwLength: usize
    ) -> usize;
}
