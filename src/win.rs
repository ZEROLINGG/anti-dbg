#![allow(unused, dead_code, non_camel_case_types, non_snake_case)]
#![cfg(windows)]
//! windows平台特有的调试检测方式

// ==============================================================================
// 全局类型与函数指针定义 (类型定义不占二进制体积，统一放置)
// ==============================================================================

/// `GetCurrentProcess`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用，遵守 `system` 调用约定。
pub type FnGetCurrentProcess = unsafe extern "system" fn() -> *mut core::ffi::c_void;
/// `GetCurrentThread`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用，遵守 `system` 调用约定。
pub type FnGetCurrentThread = unsafe extern "system" fn() -> *mut core::ffi::c_void;
/// `CloseHandle`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；传入的句柄须有效。
pub type FnCloseHandle = unsafe extern "system" fn(*mut core::ffi::c_void) -> i32;
/// `GetLastError`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用，遵守 `system` 调用约定。
pub type FnGetLastError = unsafe extern "system" fn() -> u32;
/// `SetLastError`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用，遵守 `system` 调用约定。
pub type FnSetLastError = unsafe extern "system" fn(u32);
/// `IsDebuggerPresent`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用，遵守 `system` 调用约定。
pub type FnIsDebuggerPresent = unsafe extern "system" fn() -> i32;
/// `CheckRemoteDebuggerPresent`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；输出指针须指向可写 `i32`。
pub type FnCheckRemoteDebuggerPresent =
    unsafe extern "system" fn(*mut core::ffi::c_void, *mut i32) -> i32;
/// `NtQueryInformationProcess`（ntdll.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；缓冲指针与长度须匹配。
pub type FnNtQueryInformationProcess = unsafe extern "system" fn(
    *mut core::ffi::c_void,
    u32,
    *mut core::ffi::c_void,
    u32,
    *mut u32,
) -> i32;
/// `GetThreadContext`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；上下文指针须有效。
pub type FnGetThreadContext =
    unsafe extern "system" fn(*mut core::ffi::c_void, *mut core::ffi::c_void) -> i32;
/// `AddVectoredExceptionHandler`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；回调须为合法异常处理函数。
pub type FnAddVectoredExceptionHandler = unsafe extern "system" fn(
    u32,
    Option<unsafe extern "system" fn(*mut core::ffi::c_void) -> i32>,
) -> *mut core::ffi::c_void;
/// `RemoveVectoredExceptionHandler`（kernel32.dll）的动态解析函数指针类型。
///
/// # Safety
///
/// 须经 `resolve` 获取有效地址后在 `unsafe` 块中调用；句柄须为已注册值。
pub type FnRemoveVectoredExceptionHandler =
    unsafe extern "system" fn(*mut core::ffi::c_void) -> u32;

// CONTEXT 结构体较大，仅在硬件断点或异常检测时编译
#[cfg(any(feature = "win_checks_hw", feature = "win_checks_exception"))]
/// XMM 寄存器槽位（`CONTEXT.VectorRegister` 数组元素，`#[repr(C)]` 与系统定义对齐）。
#[repr(C)]
#[derive(Clone, Copy)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

#[cfg(any(feature = "win_checks_hw", feature = "win_checks_exception"))]
impl Default for M128A {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(all(
    any(feature = "win_checks_hw", feature = "win_checks_exception"),
    any(target_arch = "arm64ec", target_arch = "x86_64")
))]
#[repr(C)]
#[derive(Clone, Copy)]
/// x86_64/arm64ec 线程上下文（含 `Dr0~Dr7` 硬件断点寄存器，`#[repr(C)]` 与系统定义对齐）。
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
    pub Anonymous: [u64; 64],
    pub VectorRegister: [M128A; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

#[cfg(all(
    any(feature = "win_checks_hw", feature = "win_checks_exception"),
    any(target_arch = "arm64ec", target_arch = "x86_64")
))]
impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(feature = "win_checks_exception")]
static WIN_ANTI_DBG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

// ==============================================================================
// 1. API 查询类 (Feature: win_checks_api)
// ==============================================================================

#[cfg(feature = "win_checks_api")]
pub const PROCESS_DEBUG_PORT: u32 = 7;
#[cfg(feature = "win_checks_api")]
pub const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 30;
#[cfg(feature = "win_checks_api")]
pub const PROCESS_DEBUG_FLAGS: u32 = 31;

#[cfg(feature = "win_checks_api")]
unsafe fn query_process_info<T: Default>(info_class: u32) -> Option<T> {
    let get_curr_proc =
        lib_unknown::sys::win::resolve::<FnGetCurrentProcess>("kernel32.dll", "GetCurrentProcess")?;
    let nt_query = lib_unknown::sys::win::resolve::<FnNtQueryInformationProcess>(
        "ntdll.dll",
        "NtQueryInformationProcess",
    )?;
    unsafe {
        let mut value = T::default();
        let status = nt_query(
            get_curr_proc(),
            info_class,
            &mut value as *mut _ as *mut _,
            size_of::<T>() as u32,
            core::ptr::null_mut(),
        );
        if status == 0 { Some(value) } else { None }
    }
}

/// 调用 `IsDebuggerPresent`（需启用 `win_checks_api` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效；Linux 下编译通过但调用无意义，故不做 doctest。
/// use anti_dbg::win::is_debugger_present;
///
/// let _ = is_debugger_present();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_api"` 特性。
#[cfg(feature = "win_checks_api")]
pub fn is_debugger_present() -> bool {
    lib_unknown::sys::win::resolve::<FnIsDebuggerPresent>("kernel32.dll", "IsDebuggerPresent")
        .map_or(false, |f| unsafe { f() != 0 })
}

/// 调用 `CheckRemoteDebuggerPresent`（需启用 `win_checks_api` 特性）。
///
/// 解析失败返回 `None`。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_remote_debugger_present;
///
/// let _ = check_remote_debugger_present();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_api"` 特性。
#[cfg(feature = "win_checks_api")]
pub fn check_remote_debugger_present() -> Option<bool> {
    let get_curr_proc =
        lib_unknown::sys::win::resolve::<FnGetCurrentProcess>("kernel32.dll", "GetCurrentProcess")?;
    let check_remote = lib_unknown::sys::win::resolve::<FnCheckRemoteDebuggerPresent>(
        "kernel32.dll",
        "CheckRemoteDebuggerPresent",
    )?;
    unsafe {
        let current_process = get_curr_proc();
        let mut being_debugged: i32 = 0;
        if check_remote(current_process, &mut being_debugged) != 0 {
            Some(being_debugged != 0)
        } else {
            None
        }
    }
}

/// 查询进程 `DebugPort` 是否非零（需启用 `win_checks_api` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_debug_port;
///
/// let _ = check_debug_port();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_api"` 特性。
#[cfg(feature = "win_checks_api")]
pub fn check_debug_port() -> Option<bool> {
    unsafe { query_process_info::<usize>(PROCESS_DEBUG_PORT).map(|port| port != 0) }
}

/// 查询进程 `DebugObjectHandle` 是否非空（需启用 `win_checks_api` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_debug_object;
///
/// let _ = check_debug_object();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_api"` 特性。
#[cfg(feature = "win_checks_api")]
pub fn check_debug_object() -> Option<bool> {
    unsafe {
        query_process_info::<*mut core::ffi::c_void>(PROCESS_DEBUG_OBJECT_HANDLE)
            .map(|handle| !handle.is_null())
    }
}

/// 检查 `NoDebugInherit` 标志是否被清零（需启用 `win_checks_api` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_debug_flags;
///
/// let _ = check_debug_flags();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_api"` 特性。
#[cfg(feature = "win_checks_api")]
pub fn check_debug_flags() -> Option<bool> {
    unsafe { query_process_info::<u32>(PROCESS_DEBUG_FLAGS).map(|flags| flags == 0) }
}

// ==============================================================================
// 2. PEB 内存读取类 (Feature: win_checks_peb)
// ==============================================================================

#[cfg(feature = "win_checks_peb")]
/// `NtGlobalFlag` 调试标志掩码（`0x70`）。
pub const DEBUG_FLAGS: u32 = 0x70;

#[cfg(all(feature = "win_checks_peb", target_arch = "x86_64"))]
/// PEB 内 `NtGlobalFlag` 字段偏移（x86_64）。
pub const PEB_NT_GLOBAL_FLAG_OFFSET: usize = 0xBC;
#[cfg(all(feature = "win_checks_peb", target_arch = "x86"))]
/// PEB 内 `NtGlobalFlag` 字段偏移（x86）。
pub const PEB_NT_GLOBAL_FLAG_OFFSET: usize = 0x68;

#[cfg(feature = "win_checks_peb")]
#[repr(C)]
/// 精简 PEB 头（仅含定位 `BeingDebugged` 所需的前缀字段）。
pub struct PEB {
    pub reserved1: [u8; 2],
    pub being_debugged: u8,
}

#[cfg(all(
    feature = "win_checks_peb",
    any(target_arch = "x86_64", target_arch = "x86")
))]
unsafe fn get_peb() -> *const PEB {
    let peb: *const PEB;
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("mov {}, gs:[0x60]", out(reg) peb, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86")]
    unsafe {
        ::core::arch::asm!("mov {}, fs:[0x30]", out(reg) peb, options(nostack, preserves_flags));
    }
    peb
}

#[cfg(all(
    feature = "win_checks_peb",
    not(any(target_arch = "x86_64", target_arch = "x86"))
))]
unsafe fn get_peb() -> *const PEB {
    ::core::ptr::null()
}

/// 经 GS/FS 段寄存器读取 PEB 的 `BeingDebugged` 字节（需启用 `win_checks_peb` 特性）。
///
/// 非 x86 系架构恒返回 `None`。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_peb_being_debugged;
///
/// let _ = check_peb_being_debugged();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_peb"` 特性。
#[cfg(feature = "win_checks_peb")]
pub fn check_peb_being_debugged() -> Option<bool> {
    unsafe {
        let peb = get_peb();
        if peb.is_null() {
            return None;
        }
        Some((*peb).being_debugged != 0)
    }
}

/// 检查 PEB 偏移处的 `NtGlobalFlag` 是否含调试标志（需启用 `win_checks_peb` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_peb_nt_global_flag;
///
/// let _ = check_peb_nt_global_flag();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_peb"` 特性。
#[cfg(feature = "win_checks_peb")]
pub fn check_peb_nt_global_flag() -> Option<bool> {
    unsafe {
        let peb = get_peb() as *const u8;
        if peb.is_null() {
            return None;
        }
        let nt_global_flag = *(peb.add(PEB_NT_GLOBAL_FLAG_OFFSET) as *const u32);
        Some((nt_global_flag & DEBUG_FLAGS) != 0)
    }
}

// ==============================================================================
// 3. 硬件断点检测类 (Feature: win_checks_hw)
// ==============================================================================

#[cfg(all(feature = "win_checks_hw", target_arch = "x86_64"))]
/// `GetThreadContext` 读取调试寄存器的标志（x86_64）。
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x100010;
#[cfg(all(feature = "win_checks_hw", target_arch = "x86"))]
/// `GetThreadContext` 读取调试寄存器的标志（x86）。
pub const CONTEXT_DEBUG_REGISTERS: u32 = 0x10010;

#[cfg(feature = "win_checks_hw")]
/// 检查 `Dr0~Dr3` 硬件断点寄存器是否被设置（需启用 `win_checks_hw` 特性）。
///
/// # Examples
///
/// ```rust,ignore
/// // 仅 Windows 生效，不做 doctest。
/// use anti_dbg::win::check_hardware_breakpoints;
///
/// let _ = check_hardware_breakpoints();
/// ```
///
/// # Feature Requirement
///
/// 需要启用 `"win_checks_hw"` 特性。
pub fn check_hardware_breakpoints() -> Option<bool> {
    let get_curr_thread =
        lib_unknown::sys::win::resolve::<FnGetCurrentThread>("kernel32.dll", "GetCurrentThread")?;
    let get_thread_ctx =
        lib_unknown::sys::win::resolve::<FnGetThreadContext>("kernel32.dll", "GetThreadContext")?;
    unsafe {
        #[cfg(any(target_arch = "x86_64", target_arch = "arm64ec"))]
        {
            let mut context = CONTEXT::default();
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if get_thread_ctx(get_curr_thread(), &mut context as *mut _ as *mut _) != 0 {
                Some(context.Dr0 != 0 || context.Dr1 != 0 || context.Dr2 != 0 || context.Dr3 != 0)
            } else {
                None
            }
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "arm64ec")))]
        ::core::option::Option::Some(false)
    }
}

// ==============================================================================
// 4. 异常机制对抗类 (Feature: win_checks_exception)
// ==============================================================================

#[cfg(feature = "win_checks_exception")]
pub const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = (-1isize) as *mut core::ffi::c_void;
#[cfg(feature = "win_checks_exception")]
pub const EXCEPTION_BREAKPOINT: i32 = 0x80000003_u32 as _;
#[cfg(feature = "win_checks_exception")]
pub const EXCEPTION_INVALID_HANDLE: i32 = 0xC0000008_u32 as _;
#[cfg(feature = "win_checks_exception")]
pub const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
#[cfg(feature = "win_checks_exception")]
pub const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
#[cfg(feature = "win_checks_exception")]
pub const ERROR_INVALID_HANDLE: u32 = 6;

#[cfg(feature = "win_checks_exception")]
pub static EXPECTED_INT3_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "win_checks_exception")]
pub static VEH_EXCEPTION_CAUGHT: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

#[cfg(feature = "win_checks_exception")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: i32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut core::ffi::c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [usize; 15],
}
#[cfg(feature = "win_checks_exception")]
impl Default for EXCEPTION_RECORD {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(feature = "win_checks_exception")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut core::ffi::c_void,
}
#[cfg(feature = "win_checks_exception")]
impl Default for EXCEPTION_POINTERS {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[cfg(feature = "win_checks_exception")]
unsafe extern "system" fn int3_exception_handler(
    exception_info_ptr: *mut core::ffi::c_void,
) -> i32 {
    unsafe {
        if exception_info_ptr.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }
        let exception_info = exception_info_ptr as *mut EXCEPTION_POINTERS;
        let exception_record_ptr = (*exception_info).ExceptionRecord;
        let context_record_ptr = (*exception_info).ContextRecord;
        if exception_record_ptr.is_null() || context_record_ptr.is_null() {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let exception_record = &*exception_record_ptr;
        if exception_record.ExceptionCode != EXCEPTION_BREAKPOINT {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        let expected_addr = EXPECTED_INT3_ADDR.load(core::sync::atomic::Ordering::SeqCst);
        let actual_addr = exception_record.ExceptionAddress as u64;
        if expected_addr == 0 || actual_addr != expected_addr {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        VEH_EXCEPTION_CAUGHT.store(true, core::sync::atomic::Ordering::SeqCst);

        #[cfg(target_arch = "x86_64")]
        {
            (*(context_record_ptr as *mut CONTEXT)).Rip += 1;
        }

        EXCEPTION_CONTINUE_EXECUTION
    }
}

#[cfg(all(feature = "win_checks_exception", target_arch = "x86_64"))]
pub fn is_debugger_present_via_int3() -> bool {
    struct VehGuard(*mut core::ffi::c_void);
    impl Drop for VehGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                if let Some(remove_veh) = lib_unknown::sys::win::resolve::<
                    FnRemoveVectoredExceptionHandler,
                >(
                    "kernel32.dll", "RemoveVectoredExceptionHandler"
                ) {
                    unsafe {
                        let _ = remove_veh(self.0);
                    }
                }
            }
        }
    }

    let _lock = WIN_ANTI_DBG_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    VEH_EXCEPTION_CAUGHT.store(false, core::sync::atomic::Ordering::SeqCst);
    EXPECTED_INT3_ADDR.store(0, core::sync::atomic::Ordering::SeqCst);

    let add_veh = match lib_unknown::sys::win::resolve::<FnAddVectoredExceptionHandler>(
        "kernel32.dll",
        "AddVectoredExceptionHandler",
    ) {
        Some(f) => f,
        None => return false,
    };

    unsafe {
        let handler = add_veh(1, Some(int3_exception_handler));
        if handler.is_null() {
            return false;
        }
        let _veh_guard = VehGuard(handler);
        let flag_addr = EXPECTED_INT3_ADDR.as_ptr();
        core::arch::asm!(
        "lea {tmp}, [rip + 2f]",
        "mov qword ptr [{flag_addr}], {tmp}",
        "2:", "int3",
        tmp = out(reg) _, flag_addr = in(reg) flag_addr,
        options(nostack)
        );
        EXPECTED_INT3_ADDR.store(0, core::sync::atomic::Ordering::SeqCst);
        drop(_veh_guard);
        !VEH_EXCEPTION_CAUGHT.load(core::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(all(feature = "win_checks_exception", not(target_arch = "x86_64")))]
pub fn is_debugger_present_via_int3() -> bool {
    false
}

#[cfg(feature = "win_checks_exception")]
pub fn check_close_handle_exception() -> Option<bool> {
    struct VehGuard(*mut core::ffi::c_void);
    impl Drop for VehGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                if let Some(remove_veh) = lib_unknown::sys::win::resolve::<
                    FnRemoveVectoredExceptionHandler,
                >(
                    "kernel32.dll", "RemoveVectoredExceptionHandler"
                ) {
                    unsafe {
                        let _ = remove_veh(self.0);
                    }
                }
            }
        }
    }

    static EXCEPTION_CAUGHT: core::sync::atomic::AtomicBool =
        core::sync::atomic::AtomicBool::new(false);

    unsafe extern "system" fn close_handle_exception_handler(
        exception_info_ptr: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            if exception_info_ptr.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }
            let exception_info = exception_info_ptr as *mut EXCEPTION_POINTERS;
            let exception_record_ptr = (*exception_info).ExceptionRecord;
            if exception_record_ptr.is_null() {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            let code = (*exception_record_ptr).ExceptionCode as u32;
            if code == EXCEPTION_INVALID_HANDLE as u32 {
                EXCEPTION_CAUGHT.store(true, core::sync::atomic::Ordering::SeqCst);
                return EXCEPTION_CONTINUE_EXECUTION;
            }
            EXCEPTION_CONTINUE_SEARCH
        }
    }

    let _lock = WIN_ANTI_DBG_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let add_veh = lib_unknown::sys::win::resolve::<FnAddVectoredExceptionHandler>(
        "kernel32.dll",
        "AddVectoredExceptionHandler",
    )?;
    let close_handle =
        lib_unknown::sys::win::resolve::<FnCloseHandle>("kernel32.dll", "CloseHandle")?;
    let get_last_error =
        lib_unknown::sys::win::resolve::<FnGetLastError>("kernel32.dll", "GetLastError")?;
    let set_last_error =
        lib_unknown::sys::win::resolve::<FnSetLastError>("kernel32.dll", "SetLastError")?;

    unsafe {
        EXCEPTION_CAUGHT.store(false, core::sync::atomic::Ordering::SeqCst);
        let saved_error = get_last_error();
        set_last_error(0);

        let handler = add_veh(1, Some(close_handle_exception_handler));
        if handler.is_null() {
            set_last_error(saved_error);
            return None;
        }

        let _veh_guard = VehGuard(handler);
        let invalid_handle = 0x1234_usize as *mut core::ffi::c_void;
        let _ = close_handle(invalid_handle);

        let error = get_last_error();
        let caught = EXCEPTION_CAUGHT.load(core::sync::atomic::Ordering::SeqCst);
        drop(_veh_guard);
        set_last_error(saved_error);

        if caught {
            Some(true)
        } else if error == ERROR_INVALID_HANDLE {
            Some(false)
        } else {
            None
        }
    }
}

pub fn checks(x: u8) -> bool {
    let mut checks: Vec<fn() -> bool> = Vec::with_capacity(10);

    // ============================================================
    // API
    // ============================================================

    #[cfg(feature = "win_checks_api")]
    {
        checks.push(is_debugger_present);
        checks.push(|| check_remote_debugger_present().unwrap_or(false));
        checks.push(|| check_debug_port().unwrap_or(false));
        checks.push(|| check_debug_object().unwrap_or(false));
        checks.push(|| check_debug_flags().unwrap_or(false));
    }

    // ============================================================
    // PEB
    // ============================================================

    #[cfg(feature = "win_checks_peb")]
    {
        checks.push(|| check_peb_being_debugged().unwrap_or(false));
        checks.push(|| check_peb_nt_global_flag().unwrap_or(false));
    }

    // ============================================================
    // Hardware breakpoints
    // ============================================================

    #[cfg(feature = "win_checks_hw")]
    {
        checks.push(|| check_hardware_breakpoints().unwrap_or(false));
    }

    // ============================================================
    // Exception
    // ============================================================

    #[cfg(feature = "win_checks_exception")]
    {
        checks.push(is_debugger_present_via_int3);
        checks.push(|| check_close_handle_exception().unwrap_or(false));
    }

    let checks = lib_unknown::rand::shuffle(checks);

    for check in checks.into_iter().take(x as usize) {
        if check() {
            return true;
        }
    }

    false
}
