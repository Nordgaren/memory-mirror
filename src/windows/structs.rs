#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::windows::consts::{MAX_MODULE_NAME32, MAX_PATH};
use std::mem::size_of;

#[repr(C)]
pub struct THREADENTRY32 {
    pub dwSize: u32,
    pub cntUsage: u32,
    pub th32ThreadID: u32,
    pub th32OwnerProcessID: u32,
    pub tpBasePri: i32,
    pub tpDeltaPri: i32,
    pub dwFlags: u32,
}

impl Default for THREADENTRY32 {
    fn default() -> Self {
        THREADENTRY32 {
            dwSize: size_of::<Self>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: usize,
    pub AllocationBase: usize,
    pub AllocationProtect: u32,
    #[cfg(target_arch = "x86_64")]
    pub PartitionId: u16,
    pub RegionSize: usize,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
}
#[repr(C)]
pub struct MODULEENTRY32 {
    pub dwSize: u32,
    pub th32ModuleID: u32,
    pub th32ProcessID: u32,
    pub GlblcntUsage: u32,
    pub ProccntUsage: u32,
    pub modBaseAddr: usize,
    pub modBaseSize: u32,
    pub hModule: usize,
    pub szModule: [u8; MAX_MODULE_NAME32 + 1],
    pub szExePath: [u8; MAX_PATH],
}
impl Default for MODULEENTRY32 {
    fn default() -> Self {
        MODULEENTRY32 {
            dwSize: size_of::<Self>() as u32,
            th32ModuleID: 0,
            th32ProcessID: 0,
            GlblcntUsage: 0,
            ProccntUsage: 0,
            modBaseAddr: 0,
            modBaseSize: 0,
            hModule: 0,
            szModule: [0; MAX_MODULE_NAME32 + 1],
            szExePath: [0; MAX_PATH],
        }
    }
}
