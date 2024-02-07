#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use crate::windows::consts::{MAX_MODULE_NAME32, MAX_PATH};
use std::fmt::{Debug, Formatter};
use std::mem::size_of;

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

#[repr(C)]
#[derive(Copy, Clone)]
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
#[derive(Debug, Copy, Clone, Default)]
#[allow(clippy::upper_case_acronyms)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union CONTEXT_0 {
    pub FltSave: XSAVE_FORMAT,
    pub Anonymous: CONTEXT_0_0,
}

impl Debug for CONTEXT_0 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        unsafe { write!(f, "{{ {:#?}, {:#?} }}", self.FltSave, self.Anonymous) }
    }
}

impl Default for CONTEXT_0 {
    fn default() -> Self {
        CONTEXT_0 {
            FltSave: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct XSAVE_FORMAT {
    pub ControlWord: u16,
    pub StatusWord: u16,
    pub TagWord: u8,
    pub Reserved1: u8,
    pub ErrorOpcode: u16,
    pub ErrorOffset: u32,
    pub ErrorSelector: u16,
    pub Reserved2: u16,
    pub DataOffset: u32,
    pub DataSelector: u16,
    pub Reserved3: u16,
    pub MxCsr: u32,
    pub MxCsr_Mask: u32,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [u8; 96],
}

impl Default for XSAVE_FORMAT {
    fn default() -> Self {
        XSAVE_FORMAT {
            ControlWord: Default::default(),
            StatusWord: Default::default(),
            TagWord: Default::default(),
            Reserved1: Default::default(),
            ErrorOpcode: Default::default(),
            ErrorOffset: Default::default(),
            ErrorSelector: Default::default(),
            Reserved2: Default::default(),
            DataOffset: Default::default(),
            DataSelector: Default::default(),
            Reserved3: Default::default(),
            MxCsr: Default::default(),
            MxCsr_Mask: Default::default(),
            FloatRegisters: Default::default(),
            XmmRegisters: Default::default(),
            Reserved4: [0; 96], // Amazing...
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[test]
fn check_size() {
    assert_eq!(size_of::<CONTEXT>(), 0x4D0)
}
