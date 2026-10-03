use crate::implement::Args;
use lib_unknown::rand::{seed, shuffle};
use proc_macro2::Ident;
use syn::parse::{Parse, ParseStream, Parser};
use syn::{LitBool, LitInt, Stmt, Token, parenthesized};

macro_rules! make {
    ($($tt:tt)*) => {
        Box::new(move || {
            ::syn::Block::parse_within
                .parse2(quote::quote! {
                    $($tt)*
                })
                .expect("解析生成的语句失败")
        }) as Box<dyn Fn() -> Vec<Stmt>>
    };
}

/// 生成退出/崩溃代码
///
/// - `allow_unsafe`: 如果为 false，则过滤掉所有包含 unsafe 块的代码（防止由于内存安全规则限制导致的编译报错）。
/// - `force_exit`: 如果为 true，只生成无法捕获的硬退出（如 abort、段错误、直接 exit）；
///   如果为 false，只生成能够被 `catch_unwind` 捕获的软退出（如 panic、除零、越界）。
pub fn gen_exit(allow_unsafe: bool, force_exit: bool) -> Vec<Stmt> {
    let s: u64 = seed();

    // Tuple定义: (生成AST的闭包, is_unsafe, is_force_exit)
    type MethodTuple = (Box<dyn Fn() -> Vec<Stmt>>, bool, bool);
    let mut methods: Vec<MethodTuple> = Vec::new();

    // ==========================================
    // 1. 标准安全退出方案 (Safe)
    // ==========================================

    methods.push((
        make! { ::std::process::exit(#s as i32 % 200); },
        false,
        true,
    ));

    methods.push((make! { panic!("Fatal error"); }, false, false));

    methods.push((make! { ::std::process::abort(); }, false, true));

    methods.push((make! { unreachable!(); }, false, false));

    // [Safe, 强制硬退出] - 无限递归引发栈溢出
    methods.push((
        make! {
            fn __trigger_overflow() { __trigger_overflow(); }
            __trigger_overflow();
        },
        false,
        true,
    ));

    // [Safe, 强制硬退出] - 双重恐慌 (Double Panic / Drop Bomb)
    // 原理：在展开 Panic 的过程中再次触发 Panic 会导致 Rust 运行时直接 abort
    methods.push((
        make! {
            struct DropBomb;
            impl ::core::ops::Drop for DropBomb {
                fn drop(&mut self) {
                    panic!("Double panic trigger!");
                }
            }
            let _bomb = DropBomb;
            panic!("First panic!");
        },
        false,
        true,
    ));

    // [Safe, 软退出] - 除零
    methods.push((
        make! {
            let zero = #s as usize - #s as usize;
            let _ = 1 / zero;
        },
        false,
        false,
    ));

    // [Safe, 软退出] - 数组越界
    methods.push((
        make! {
            let arr = [0u8; 16];
            let idx = #s as usize % 100 + 50;
            let _ = arr[idx];
        },
        false,
        false,
    ));

    // [Safe, 软退出] - 内存耗尽 (OOM)
    methods.push((
        make! {
            let _ = ::std::vec::Vec::<usize>::with_capacity(usize::MAX);
        },
        false,
        false,
    ));

    // ==========================================
    // 2. Unsafe 底层崩溃方案 (Unsafe)
    // ==========================================

    // [Unsafe, 强制硬退出] - Null指针写入
    methods.push((
        make! {
            unsafe {
                ::core::ptr::write_volatile(::core::ptr::null_mut::<u8>(), 0);
            }
        },
        true,
        true,
    ));

    // [Unsafe, 强制硬退出] - 直接触发未定义行为
    methods.push((
        make! {
            unsafe {
                ::core::hint::unreachable_unchecked();
            }
        },
        true,
        true,
    ));

    // [Unsafe, 强制硬退出] - 非法函数指针调用
    methods.push((
        make! {
            unsafe {
                let bad_addr = (#s as usize % 4096) + 1;
                let func: fn() = ::core::mem::transmute(bad_addr);
                func();
            }
        },
        true,
        true,
    ));

    // [Unsafe, 强制硬退出] - 篡改 .rodata (只读数据段) 引发段错误
    // 原理：字符串常量在只读页，强行写入会触发操作系统的 Access Violation
    methods.push((
        make! {
            unsafe {
                let ro_string = "Access";
                let ptr = ro_string.as_ptr() as *mut u8;
                ::core::ptr::write_volatile(ptr, 0xFF);
            }
        },
        true,
        true,
    ));

    // [Unsafe, 软退出] - 故意制造未对齐的内存访问
    // 注意：在 x86 上可能只是性能损耗，但在 ARM/RISC-V 等架构上会引发 Bus Error
    methods.push((
        make! {
            unsafe {
                let data = [0u8; 16];
                let unaligned_addr = data.as_ptr() as usize + 1;
                let bad_ptr = unaligned_addr as *const u64;
                let _crash = ::core::ptr::read_volatile(bad_ptr);
            }
        },
        true,
        false,
    ));

    // ==========================================
    // 3. Stable 汇编级花指令与陷阱 (Asm / Unsafe)
    // ==========================================

    // [Unsafe, 强制硬退出] - 经典花指令 + UD2 (非法指令)
    // 作用：干扰 IDA / Ghidra 的线性反汇编分析，并导致程序抛出 SIGILL
    methods.push((
        make! {
            unsafe {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                ::core::arch::asm!(
                    "jmp 2f",                 // 跳过垃圾字节
                    ".byte 0xEA, 0xE8, 0xFF", // 插入垃圾字节（混淆器陷阱）
                    "2:",                     // 降落伞标签
                    "ud2",                    // 未定义指令，强制崩溃
                    options(noreturn)
                );

                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
                ::std::process::abort();
            }
        },
        true,
        true,
    ));

    // [Unsafe, 强制硬退出] - 跨平台软件断点陷阱
    // 作用：如果程序被调试器挂载，会卡死调试器；如果没有，会导致异常退出。
    methods.push((
        make! {
            unsafe {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                ::core::arch::asm!("int3", options(nomem, nostack));

                #[cfg(target_arch = "aarch64")]
                ::core::arch::asm!("brk #0", options(nomem, nostack));

                #[cfg(target_arch = "arm")]
                ::core::arch::asm!("udf #0", options(nomem, nostack));

                // 确保触发断点后程序彻底结束，不继续向下执行
                ::std::process::abort();
            }
        },
        true,
        true,
    ));

    // [Unsafe, 强制硬退出] - 制造绝对非法跳转 (向地址0跳转)
    // 作用：比 transmute 调用更底层的崩溃方式，彻底切断调用栈回溯
    methods.push((
        make! {
            unsafe {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                ::core::arch::asm!(
                    "jmp {}",
                    in(reg) 0_usize,
                    options(noreturn)
                );

                #[cfg(target_arch = "aarch64")]
                ::core::arch::asm!(
                    "br {}",
                    in(reg) 0_usize,
                    options(noreturn)
                );

                #[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
                ::std::process::abort();
            }
        },
        true,
        true,
    ));

    // ==========================================
    // 过滤与随机化返回
    // ==========================================

    methods.retain(|(_, is_unsafe, is_force)| {
        let check_unsafe = if !allow_unsafe { !*is_unsafe } else { true };
        let check_force = *is_force == force_exit;

        check_unsafe && check_force
    });

    if methods.is_empty() {
        // Fallback: 防御性编程，防止因极端条件导致列表为空
        return (make! { ::std::process::abort(); })();
    }

    methods = shuffle(methods);
    (methods.first().unwrap().0)()
}

impl Args {
    fn parse_optional_u64(input: ParseStream) -> syn::Result<Option<u64>> {
        if input.peek(syn::LitInt) {
            let value: LitInt = input.parse()?;
            Ok(Some(value.base10_parse()?))
        } else {
            let ident: Ident = input.parse()?;
            if ident == "None" {
                Ok(None)
            } else {
                Err(syn::Error::new_spanned(ident, "expected integer or None"))
            }
        }
    }
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut args = Args::default();

        if input.is_empty() {
            return Ok(args);
        }

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;

            match key.to_string().as_str() {
                "allow_loop" => {
                    args.allow_loop = input.parse::<LitBool>()?.value;
                }
                "allow_unsafe" => {
                    args.allow_unsafe = input.parse::<LitBool>()?.value;
                }
                "force_exit" => {
                    args.force_exit = input.parse::<LitBool>()?.value;
                }
                "max_depth" => {
                    args.max_depth = Self::parse_optional_u64(input)?;
                }
                "max_insertions" => {
                    args.max_insertions = Self::parse_optional_u64(input)?;
                }
                _ => {
                    return Err(syn::Error::new_spanned(
                        key.clone(),
                        format!("unknown argument: {}", key),
                    ));
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(args)
    }
}

#[derive(Debug)]
pub struct AntiArgs {
    pub insert_1: Option<Args>,
    pub insert_2: Option<Args>,
    pub insert_2_is_frist: bool,
}
impl Default for AntiArgs {
    fn default() -> AntiArgs {
        Self {
            insert_1: Some(Args::default()),
            insert_2: Some(Args::default()),
            insert_2_is_frist: false,
        }
    }
}

impl Parse for AntiArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut anti_args = AntiArgs::default();

        if input.is_empty() {
            return Ok(anti_args);
        }

        let mut is_frist = true;

        while !input.is_empty() {
            let key: Ident = input.parse()?;
            let key_str = key.to_string();

            let is_insert_1 = if key_str == "insert_1" || key_str == "a" {
                true
            } else if key_str == "insert_2" || key_str == "b" {
                false
            } else {
                return Err(syn::Error::new_spanned(
                    key,
                    "期望 `insert_1` (或 `a`) 或 `insert_2` (或 `b`)",
                ));
            };

            if is_frist {
                anti_args.insert_2_is_frist = !is_insert_1;
                is_frist = false;
            }

            if input.peek(syn::token::Paren) {
                let attr_args;
                parenthesized!(attr_args in input);
                let args: Args = attr_args.parse()?;

                if is_insert_1 {
                    anti_args.insert_1 = Some(args);
                } else {
                    anti_args.insert_2 = Some(args);
                }
            }

            if !input.is_empty() {
                input.parse::<Token![,]>()?;
            }
        }

        Ok(anti_args)
    }
}
