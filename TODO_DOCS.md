# 待处理文档清单（自动生成，勿手动大改结构）

> 首轮处理 20 项核心 API；第二轮已处理 `Fn*` 别名（11 个）、`M128A` / `CONTEXT` / `PEB`、
> `DEBUG_FLAGS` / `PEB_NT_GLOBAL_FLAG_OFFSET` / `CONTEXT_DEBUG_REGISTERS` 常量与
> `check_peb_being_debugged` / `check_peb_nt_global_flag` / `check_hardware_breakpoints`。
> 剩余记入本表。

| 序号 | 文件 | 项名称 | 原因 |
|---|---|---|---|
| 1 | src/win.rs | `EXCEPTION_RECORD` / `EXCEPTION_POINTERS` 结构体 | 留待下次；FFI 布局文档 |
| 2 | src/win.rs | `INVALID_HANDLE_VALUE` / `EXCEPTION_BREAKPOINT` / `EXCEPTION_INVALID_HANDLE` / `EXCEPTION_CONTINUE_EXECUTION` / `EXCEPTION_CONTINUE_SEARCH` / `ERROR_INVALID_HANDLE` 常量 | 同上 |
| 3 | src/win.rs | `EXPECTED_INT3_ADDR` / `VEH_EXCEPTION_CAUGHT` 静态量 | 同上；需说明原子语义 |
| 4 | src/win.rs | `is_debugger_present_via_int3`（×2，arch 条件编译）/ `check_close_handle_exception` / `checks` | 同上；`#[cfg(feature)]` 注解 + `ignore` 示例同既有 win 模式 |
| 5 | src/lib.rs | `pub use anti_dbg_macros::*` / `pub use lib_unknown as lib` 重导出 | 同上；文档在原始定义处 |

> 下次执行本技能时，若发现本文件存在，直接从表格第一行继续处理；
> 处理完成的行删除即可，无需重新探测全量覆盖率。
