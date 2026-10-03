use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, parse_macro_input};

mod implement;
mod injector;
mod tool;

use implement::Args;
use tool::AntiArgs;

#[proc_macro_attribute]
pub fn insert_1(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let func = parse_macro_input!(item as ItemFn);
    implement::insert_1(func, args).into()
}

#[proc_macro_attribute]
pub fn insert_2(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let func = parse_macro_input!(item as ItemFn);
    implement::insert_2(func, args).into()
}

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
