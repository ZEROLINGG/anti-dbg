//! `anti-dbg` 的过程宏实现 crate：函数级检测注入属性宏。
//!
//! 对外暴露 `#[anti]` / `#[insert_1]` / `#[insert_2]`，
//! 通过 `anti-dbg` 根 crate 转发（`pub use anti_dbg_macros::*`）。
use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

mod implement;
mod injector;
mod tool;

use implement::Args;
use tool::AntiArgs;

/// 向函数注入第一组反调试检测（属性参数见 `Args`）。
///
/// # Examples
///
/// ```rust,ignore
/// // 过程宏无法在定义 crate 内 doctest；暂无端到端集成测试，手动展开验证。
/// use anti_dbg::insert_1;
///
/// #[insert_1]
/// fn f() {}
/// ```
#[proc_macro_attribute]
pub fn insert_1(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let func = parse_macro_input!(item as ItemFn);
    implement::insert_1(func, args).into()
}

/// 向函数注入第二组反调试检测（属性参数见 `Args`）。
///
/// # Examples
///
/// ```rust,ignore
/// // 同 insert_1：不可 doctest，暂无集成测试。
/// use anti_dbg::insert_2;
///
/// #[insert_2]
/// fn f() {}
/// ```
#[proc_macro_attribute]
pub fn insert_2(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let func = parse_macro_input!(item as ItemFn);
    implement::insert_2(func, args).into()
}

/// 组合注入属性宏：按参数编排 `insert_1` / `insert_2` 的执行顺序。
///
/// # Examples
///
/// ```rust,ignore
/// // 同 insert_1：不可 doctest，暂无集成测试。
/// use anti_dbg::anti;
///
/// #[anti]
/// fn main() {}
/// ```
///
/// # Panics
///
/// - 内部生成的函数 TokenStream 无法重解析为合法函数时，在编译期 panic（理论不可达）。
#[proc_macro_attribute]
pub fn anti(attr: TokenStream, item: TokenStream) -> TokenStream {
    let anti_args = parse_macro_input!(attr as AntiArgs);
    let mut func = parse_macro_input!(item as ItemFn);

    if anti_args.insert_2_is_frist {
        if let Some(args) = anti_args.insert_2 {
            let ts = implement::insert_2(func, args);
            func = syn::parse2(ts).expect("insert_2 生成了无效的函数语法");
        }
        if let Some(args) = anti_args.insert_1 {
            let ts = implement::insert_1(func, args);
            func = syn::parse2(ts).expect("insert_1 生成了无效的函数语法");
        }
    } else {
        if let Some(args) = anti_args.insert_1 {
            let ts = implement::insert_1(func, args);
            func = syn::parse2(ts).expect("insert_1 生成了无效的函数语法");
        }
        if let Some(args) = anti_args.insert_2 {
            let ts = implement::insert_2(func, args);
            func = syn::parse2(ts).expect("insert_2 生成了无效的函数语法");
        }
    }

    quote!(#func).into()
}
