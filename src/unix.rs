#![allow(unused, dead_code, non_camel_case_types, non_snake_case)]
#![cfg(unix)]

use std::ffi::CStr;
use std::sync::Mutex;

use lib_unknown::sys::unix::resolve;
use lib_unknown::sys::unix::syscall::{
    SysErr, SysResult, constants, flags, ptrace_req, sys_close, sys_exit, sys_fork, sys_getpid,
    sys_open, sys_ptrace, sys_read, sys_wait4,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
static ANTI_DBG_LOCK: Mutex<()> = Mutex::new(());

// ==============================================================================
// 辅助函数：在字节切片中查找子串
// ==============================================================================
#[inline(always)]
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

// ==============================================================================
// 1. Linux/Android 特有检测 (纯 Syscall 实现，防 libc Hook)
// ==============================================================================

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn check_tracer_pid() -> Option<bool> {
    let _guard = ANTI_DBG_LOCK.lock().unwrap();
    let path = c"/proc/self/status";

    let fd = sys_open(path, flags::O_RDONLY, 0).ok()?;

    let mut buf = [0u8; 1024];
    let read_len = sys_read(fd, &mut buf).unwrap_or(0);
    let _ = sys_close(fd);

    if read_len == 0 {
        return None;
    }

    let valid_data = &buf[..read_len];
    if let Some(pos) = find_subsequence(valid_data, b"TracerPid:\t") {
        let start = pos + 11; // "TracerPid:\t".len()
        let mut end = start;
        while end < valid_data.len() && valid_data[end].is_ascii_digit() {
            end += 1;
        }

        let pid_str = core::str::from_utf8(&valid_data[start..end]).unwrap_or("0");
        let pid: i32 = pid_str.parse().unwrap_or(0);
        return Some(pid != 0);
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn check_wchan() -> Option<bool> {
    let _guard = ANTI_DBG_LOCK.lock().unwrap();
    let path = c"/proc/self/wchan";

    let fd = sys_open(path, flags::O_RDONLY, 0).ok()?;
    let mut buf = [0u8; 64];
    let read_len = sys_read(fd, &mut buf).unwrap_or(0);
    let _ = sys_close(fd);

    if read_len >= 11 {
        // "ptrace_stop" 的长度是 11
        return Some(&buf[..11] == b"ptrace_stop");
    }
    None
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn check_ptrace_traceme() -> Option<bool> {
    let _guard = ANTI_DBG_LOCK.lock().unwrap();

    const ESRCH: isize = 3; // No such process
    const EINTR: isize = 4; // Interrupted system call (中断)

    #[inline(always)]
    fn wifexited(status: i32) -> bool {
        (status & 0x7f) == 0
    }

    #[inline(always)]
    fn wexitstatus(status: i32) -> i32 {
        (status & 0xff00) >> 8
    }

    let trap_res = sys_ptrace(ptrace_req::PTRACE_PEEKTEXT, -1, 0, 0);
    match trap_res {
        Err(SysErr::Ret(err)) if err == ESRCH => { /* 符合预期 */ }
        _ => return Some(true),
    }

    let parent_pid = sys_getpid() as isize;

    let pid = match sys_fork() {
        Ok(p) => p,
        Err(_) => return None,
    };

    if pid == 0 {
        // ---------------- 子进程逻辑 ----------------
        if sys_ptrace(ptrace_req::PTRACE_ATTACH, parent_pid, 0, 0).is_ok() {
            let mut status: i32 = 0;
            // 此时父进程变为当前子进程的 Tracee，允许合法 wait4
            let _ = sys_wait4(
                parent_pid,
                &mut status as *mut i32,
                0,
                core::ptr::null_mut(),
            );
            let _ = sys_ptrace(ptrace_req::PTRACE_DETACH, parent_pid, 0, 0);
            sys_exit(0);
        } else {
            sys_exit(1);
        }
    } else {
        // ---------------- 父进程逻辑 ----------------
        let mut status: i32 = 0;

        // 必须套在 loop 里处理系统调用中断
        loop {
            let ret = sys_wait4(
                pid as isize,
                &mut status as *mut i32,
                0,
                core::ptr::null_mut(),
            );

            match ret {
                Ok(_) => {
                    // 子进程正常退出
                    if wifexited(status) {
                        let exit_code = wexitstatus(status);
                        return Some(exit_code == 1);
                    }

                    // 如果状态是停止 (WIFSTOPPED: 0x7f)，继续等待
                    if (status & 0xff) == 0x7f {
                        continue;
                    }

                    // 子进程被信号异常杀死，说明环境不稳定，退出
                    break;
                }
                Err(SysErr::Ret(err)) if err == EINTR => {
                    // 父进程被 attach 后收到 SIGSTOP 会中断系统调用返回 EINTR
                    // 此时必须 continue，等待 Detach 恢复并拿到最终的 exit code
                    continue;
                }
                Err(_) => {
                    // 其他系统调用失败 (如 ECHILD)
                    break;
                }
            }
        }

        None
    }
}

// ==============================================================================
// 2. macOS/iOS 特有检测
// ==============================================================================

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn check_sysctl_ptrace() -> Option<bool> {
    const CTL_KERN: i32 = 1;
    const KERN_PROC: i32 = 14;
    const KERN_PROC_PID: i32 = 1;
    const P_TRACED: i32 = 0x00000800;

    type SysctlFn = unsafe extern "C" fn(
        name: *mut i32,
        namelen: u32,
        oldp: *mut core::ffi::c_void,
        oldlenp: *mut usize,
        newp: *mut core::ffi::c_void,
        newlen: usize,
    ) -> i32;

    let sysctl = resolve::<SysctlFn>("libc.dylib", "sysctl")?;

    unsafe {
        let pid = sys_getpid() as i32;
        let mut mib = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid];
        let mut kinfo: [u8; 1024] = [0; 1024];
        let mut size: usize = kinfo.len();

        let ret = sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            kinfo.as_mut_ptr() as *mut core::ffi::c_void,
            &mut size,
            core::ptr::null_mut(),
            0,
        );

        if ret == 0 && size > 0 {
            let p_flag_ptr = kinfo.as_ptr().add(32) as *const i32;
            let p_flag = core::ptr::read_unaligned(p_flag_ptr);
            return Some((p_flag & P_TRACED) != 0);
        }
    }
    None
}

// ==============================================================================
// 3. 通用 Unix 检测 (环境与动态库)
// ==============================================================================

pub fn check_suspicious_dylibs() -> Option<bool> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let suspicious_keywords: &[&[u8]] = &[
            b"frida",
            b"xposed",
            b"lsposed",
            b"edxposed",
            b"magisk",
            b"riru",
            b"zygisk",
            b"sandhook",
            b"xhook",
            b"substrate",
            b"qemu",
            b"valgrind",
            b"libmemtrack",
        ];

        let path = c"/proc/self/maps";
        let fd = sys_open(path, flags::O_RDONLY, 0).ok()?;

        let mut buf = [0u8; 4096];
        let mut found = false;

        // 块读取 (Chunked Read)
        while let Ok(read_len) = sys_read(fd, &mut buf) {
            if read_len == 0 {
                break;
            }
            let chunk = &buf[..read_len];

            for &k in suspicious_keywords {
                if find_subsequence(chunk, k).is_some() {
                    found = true;
                    break;
                }
            }
            if found {
                break;
            }
        }
        let _ = sys_close(fd);
        Some(found)
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        type DyldImageCount = unsafe extern "C" fn() -> u32;
        type DyldGetImageName = unsafe extern "C" fn(u32) -> *const std::ffi::c_char;

        let _dyld_image_count = resolve::<DyldImageCount>("libc.dylib", "_dyld_image_count")?;
        let _dyld_get_image_name =
            resolve::<DyldGetImageName>("libc.dylib", "_dyld_get_image_name")?;

        let suspicious_keywords = [
            "frida",
            "cycript",
            "cydia",
            "substrate",
            "substitute",
            "tweakinject",
            "mobilehooker",
            "flex",
            "sslkillswitch",
            "chisel",
        ];

        unsafe {
            let count = _dyld_image_count();
            for i in 0..count {
                let name_ptr = _dyld_get_image_name(i);
                if name_ptr.is_null() {
                    continue;
                }

                if let Ok(c_str) = CStr::from_ptr(name_ptr).to_str() {
                    let lower_name = c_str.to_ascii_lowercase();
                    if suspicious_keywords.iter().any(|&k| lower_name.contains(k)) {
                        return Some(true);
                    }
                }
            }
        }
        Some(false)
    }
}

pub fn check_env() -> bool {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let bad_envs: &[&[u8]] = &[
            b"LD_PRELOAD=",
            b"LD_AUDIT=",
            b"LD_DEBUG=",
            b"FRIDA_SERVER=",
            b"_JAVA_OPTIONS=",
            b"QEMU_SET_ENV=",
        ];
        let path = c"/proc/self/environ";
        if let Ok(fd) = sys_open(path, flags::O_RDONLY, 0) {
            let mut buf = [0u8; 2048];
            if let Ok(len) = sys_read(fd, &mut buf) {
                let chunk = &buf[..len];
                let _ = sys_close(fd);
                for &env in bad_envs {
                    if find_subsequence(chunk, env).is_some() {
                        return true;
                    }
                }
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let bad_envs = [
            "DYLD_INSERT_LIBRARIES",
            "MallocStackLogging",
            "MallocScribble",
            "MallocPreScribble",
            "MallocGuardEdges",
            "OS_ACTIVITY_DT_MODE",
            "NSZombiesEnabled",
        ];
        if bad_envs.iter().any(|&env| std::env::var(env).is_ok()) {
            return true;
        }
    }

    false
}

pub fn checks(x: u8) -> bool {
    let mut checks: Vec<fn() -> bool> = Vec::with_capacity(10);

    checks.push(|| check_suspicious_dylibs().unwrap_or(false));
    checks.push(check_env);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        checks.push(|| check_tracer_pid().unwrap_or(false));
        checks.push(|| check_wchan().unwrap_or(false));
        checks.push(|| check_ptrace_traceme().unwrap_or(false));
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        checks.push(|| check_sysctl_ptrace().unwrap_or(false));
    }

    let checks = lib_unknown::rand::shuffle(checks);

    for check in checks.into_iter().take(x as usize) {
        if check() {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use crate::checks;
    use crate::unix::{check_env, check_suspicious_dylibs, check_tracer_pid, check_wchan};

    #[test]
    fn check_any() {
        dbg!(check_env());
        dbg!(check_wchan());
        dbg!(check_tracer_pid());
        dbg!(check_suspicious_dylibs());
        dbg!(checks(5));
    }
}
