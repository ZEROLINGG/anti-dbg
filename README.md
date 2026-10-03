# anti-dbg

> **反调试检测库：环境检查 + 时钟混淆 + 编译期检测注入**

`#[anti]` 过程宏向函数注入随机化反调试检测，运行时检测 API 覆盖 Windows / Unix 双平台。

底层随机数与系统调用来自 [`lib-unknown`](https://github.com/ZEROLINGG/lib-unknown)。

## 快速开始

```toml
[dependencies]
anti-dbg = "0.1"
```

```rust
use anti_dbg::{checks, pow_sleep, verify_sleep};

fn main() {
    // 综合检测：随机抽取若干项检查，任一命中返回 true
    if checks(5) {
        std::process::exit(1);
    }
    // 时钟混淆睡眠 + 自校验
    let s = pow_sleep(10.0);
    assert!(verify_sleep(s, 10.0));
}
```

```rust
use anti_dbg::anti;

// 向函数注入反调试检测（属性参数见 anti-dbg-macros 文档）
#[anti]
fn main() {
    println!("protected");
}
```

## API 一览

| 入口 | 说明 |
|---|---|
| `checks(x)` | 平台相关的综合检测入口（`x` 为随机抽查强度） |
| `pow_sleep(ms)` / `verify_sleep(s, ms)` | PoW 式忙等睡眠及其耗时自校验 |
| `probe()` | 单调时钟探针（1GHz 归一化） |
| `unix::{check_tracer_pid, check_wchan, check_ptrace_traceme, check_sysctl_ptrace, check_suspicious_dylibs, check_env}` | Linux / macOS 侧检测项 |
| `win::{is_debugger_present, check_remote_debugger_present, check_debug_port, check_peb_being_debugged, check_hardware_breakpoints, ...}` | Windows 侧检测项（PEB / 调试端口 / 硬件断点 / VEH 异常等） |
| `#[anti]` / `#[insert_1]` / `#[insert_2]` | 编译期检测注入属性宏 |

## 特性标志 (Feature Flags)

| Feature | 默认启用 | 说明 |
| :--- | :--- | :--- |
| `win_checks_all` | ✅ | 全部 Windows 检测项的总开关 |
| `win_checks_api` | ❌ | `IsDebuggerPresent` 等 API 类检测 |
| `win_checks_peb` | ❌ | PEB（BeingDebugged / NtGlobalFlag）类检测 |
| `win_checks_hw` | ❌ | 硬件断点寄存器类检测 |
| `win_checks_exception` | ❌ | VEH / int3 / CloseHandle 异常类检测 |

## 平台与环境支持

- **操作系统**：Linux / macOS / Windows（`checks()` 按平台分发）。
- 检测函数返回 `bool` 或 `Option<bool>`（`None` 表示当前环境不支持该项）。

## 最小 Rust 版本 (MSRV)

MSRV 未在 `Cargo.toml` 声明，在 `rustc 1.98.1` 测试稳定。

## 开源协议

[MIT License](LICENSE)
