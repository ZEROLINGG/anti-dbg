# Changelog

本文件记录本项目所有值得关注的变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本 2.0.0](https://semver.org/lang/zh-CN/)。

> **版本号说明（0.x 阶段）**：在 1.0.0 发布之前，次版本号（`0.MINOR.0`）的变更
> 也可能包含破坏性改动，请留意标注为 **[BREAKING]** 的条目。

---

## [未发布] (Unreleased)

### 新增 (Added)
-

### 变更 (Changed)
-

### 修复 (Fixed)
-

---

## [0.1.0] - 2026-10-03

### 新增 (Added)

- 首个版本：`anti-dbg` 根 crate（`checks` / `pow_sleep` / `verify_sleep` / `probe`）与 `anti-dbg-macros` 过程宏 crate（`#[anti]` / `#[insert_1]` / `#[insert_2]`）
- Unix 检测：`check_tracer_pid` / `check_wchan` / `check_ptrace_traceme` / `check_sysctl_ptrace` / `check_suspicious_dylibs` / `check_env`
- Windows 检测：API / PEB / 硬件断点 / VEH 异常四类（`win_checks_*` 特性门控）
- 底层依赖为 crates.io `lib-unknown = "0.1"`
- `README.md`（简体中文）与 `anti-dbg-macros/README.md` 指向说明
- 核心公开 API rustdoc（含 doctest）与 `TODO_DOCS.md` 余量清单
