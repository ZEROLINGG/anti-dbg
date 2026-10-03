// anti-dbg/macros/src/implement.rs
use crate::injector::{PairStatementInjector, StatementInjector};
use crate::tool::gen_exit;
use lib_unknown::rand::{next, random, random_range, shuffle};
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{ItemFn, parse::Parser, visit_mut::VisitMut};

macro_rules! parse {
    ($($tt:tt)*) => {
        ::syn::Block::parse_within
            .parse2(quote::quote! {
                $($tt)*
            })
            .expect("解析生成的语句失败")
    };
}

#[derive(Debug)]
pub struct Args {
    pub allow_loop: bool,
    pub allow_unsafe: bool,
    pub force_exit: bool,
    pub max_depth: Option<u64>,
    pub max_insertions: Option<u64>,
}
impl Default for Args {
    fn default() -> Self {
        Self {
            allow_loop: false,
            allow_unsafe: true,
            force_exit: false,
            max_depth: Some(5),
            max_insertions: Some(50),
        }
    }
}

pub fn insert_1(mut func: ItemFn, args: Args) -> TokenStream2 {
    let mut injector = StatementInjector::new(
        args.allow_loop,
        args.max_depth,
        args.max_insertions,
        || None,
        |s, _| {
            let exit = gen_exit(args.allow_unsafe, args.force_exit);
            Some(parse! { if ::anti_dbg::checks(const {(#s as u8 % 4) + 5}) {
                #(#exit)*
            }; })
        },
        next,
    );
    injector.visit_block_mut(&mut func.block);
    quote!(#func)
}

// 深度多态优化的反调试/反篡改注入 (开销较大)
pub fn insert_2(mut func: ItemFn, args: Args) -> TokenStream2 {
    let fn_id = random::<u64>();
    let fn_history_ident = format_ident!("__anti_dbg_history_{fn_id}");
    let fn_record_ident = format_ident!("__anti_dbg_record_{fn_id}");

    let mut injector = PairStatementInjector::new(
        args.allow_loop,
        args.max_depth,
        args.max_insertions,
        || {
            let history_logic = match random_range(0..3) {
                0 => parse! {
                    let mut #fn_history_ident: u8 = 0;
                    let mut #fn_record_ident = |is_err: bool| -> bool {
                        #fn_history_ident <<= 1;
                        if is_err { #fn_history_ident |= 1; }
                        #fn_history_ident.count_ones() >= 4
                    };
                },
                1 => parse! {
                    let mut #fn_history_ident: usize = 0;
                    let mut #fn_record_ident = |is_err: bool| -> bool {
                        if is_err { #fn_history_ident += 1; }
                        #fn_history_ident >= 4
                    };
                },
                _ => parse! {
                    let mut #fn_history_ident = [false; 5];
                    let mut idx = 0;
                    let mut #fn_record_ident = |is_err: bool| -> bool {
                        #fn_history_ident[idx % 5] = is_err;
                        idx += 1;
                        #fn_history_ident.iter().filter(|&&x| x).count() >= 3
                    };
                },
            };
            Some(history_logic)
        },
        |id, _| {
            let id_sleep = format_ident!("__tmp_sleep_{id}");
            let id_t_inst = format_ident!("__tmp_t_inst_{id}");
            let id_t_sys = format_ident!("__tmp_t_sys_{id}");
            let id_t_probe = format_ident!("__tmp_t_probe_{id}");
            let id_handles = format_ident!("__tmp_handles_{id}");

            let thread_count = random_range(3..7); // 3 ~ 6
            let sleep_val = random_range(70.0..100.0);

            // 5% ~ 8% 系统时间与单调时间的误差
            let systime_drift_threshold = random_range(0.05..0.08);

            // cpu/时钟频率
            let min_mhz = random_range(500u64..600u64);
            let max_mhz = random_range(8000u64..8500u64);

            // 最小系统抖动 0.05 ~ 0.15 ms
            let jitter = random_range(0.05..0.15);

            // 单调时钟与pow延时误差
            let pow_drift_threshold_up = random_range(2.50..2.65);
            let pow_drift_threshold_down = -random_range(0.29f64..0.32f64);

            let exit_hard_0 = gen_exit(args.allow_unsafe, args.force_exit);
            let exit_hard_1 = gen_exit(args.allow_unsafe, args.force_exit);
            let exit_hard_2 = gen_exit(args.allow_unsafe, args.force_exit);
            let exit_hard_3 = gen_exit(args.allow_unsafe, args.force_exit);
            let exit_hard_4 = gen_exit(args.allow_unsafe, args.force_exit);
            let exit_soft = gen_exit(args.allow_unsafe, args.force_exit);

            // 初始化块
            let mut init = parse! {
                let #id_sleep = #sleep_val;
                let #id_t_inst = ::std::time::Instant::now();
                let #id_t_sys = ::std::time::SystemTime::now();
                let #id_t_probe = ::anti_dbg::probe();
                let mut #id_handles = ::std::vec::Vec::with_capacity(#thread_count as usize);
            };

            let is_tuple_zero = random::<bool>();
            let thread_closure = if is_tuple_zero {
                quote! {
                    move || {
                        let p = ::anti_dbg::pow_sleep(#id_sleep);
                        let t_inst = ::std::time::Instant::now();
                        let t_sys = ::std::time::SystemTime::now();
                        let t_probe = ::anti_dbg::probe(); // (统一1GHz标准)
                        (p, t_inst, t_sys, t_probe)
                    }
                }
            } else {
                quote! {
                    move || {
                        let p = ::anti_dbg::pow_sleep(#id_sleep);
                        let t_inst = ::std::time::Instant::now();
                        let t_sys = ::std::time::SystemTime::now();
                        let t_probe = ::anti_dbg::probe();
                        (t_inst, p, t_probe, t_sys)
                    }
                }
            };

            for _ in 0..thread_count {
                init.extend(parse! {
                    #id_handles.push(::std::thread::spawn(#thread_closure));
                });
            }

            let val_pow = if is_tuple_zero {
                quote! { val.0 }
            } else {
                quote! { val.1 }
            };
            let val_inst = if is_tuple_zero {
                quote! { val.1 }
            } else {
                quote! { val.0 }
            };
            let val_sys = if is_tuple_zero {
                quote! { val.2 }
            } else {
                quote! { val.3 }
            };
            let val_probe = if is_tuple_zero {
                quote! { val.3 }
            } else {
                quote! { val.2 }
            };

            let mut checks_a = vec![];

            checks_a.push(quote! {
                if (dur_inst - dur_sys).abs() / dur_inst > #systime_drift_threshold { #(#exit_hard_1)* }
            });

            if random::<bool>() {
                checks_a.push(quote! {
                    let mhz = (delta_probe / dur_inst as u64) / 1000;
                    if mhz < #min_mhz || mhz > #max_mhz { #(#exit_hard_2)* }
                });
            } else {
                checks_a.push(quote! {
                    let total_probe_k = delta_probe / 1000;
                    let lower_bound = #min_mhz * dur_inst as u64;
                    let upper_bound = #max_mhz * dur_inst as u64;
                    if total_probe_k < lower_bound || total_probe_k > upper_bound { #(#exit_hard_2)* }
                });
            }

            checks_a.push(quote! {
                for val in &values {
                    let i_dur = (#val_inst - #id_t_inst).as_secs_f64() * 1000.0;
                    let s_dur = #val_sys.duration_since(#id_t_sys).unwrap_or_default().as_secs_f64() * 1000.0;
                    let t_del = #val_probe.saturating_sub(#id_t_probe);
                    // 子线程结束时间绝对不可能大于主线程 join 返回的时间
                    if i_dur > dur_inst || s_dur > dur_sys || t_del > delta_probe {
                        #(#exit_hard_3)*
                    }
                }
            });

            checks_a = shuffle(checks_a);

            let mut checks_b = vec![];

            checks_b.push(quote! {
                let len = elapseds.len();
                if len >= 3 && (elapseds[len - 1] - elapseds[0]) < #jitter {
                    #(#exit_hard_4)*
                }
            });

            checks_b.push(quote! {
                let len = elapseds.len();
                let median = if len % 2 == 0 {
                    (elapseds[len / 2 - 1] + elapseds[len / 2]) / 2.0
                } else {
                    elapseds[len / 2]
                };
                let err_ratio = (median - #id_sleep) / #id_sleep;
                if err_ratio < #pow_drift_threshold_down || err_ratio > #pow_drift_threshold_up {
                    is_soft_err = true;
                }
            });

            checks_b = shuffle(checks_b);

            let check_stream = quote! {
                {
                    let mut values = ::std::vec::Vec::with_capacity(#thread_count as usize);
                    let mut is_soft_err = false;

                    for handle in #id_handles {
                        match handle.join() {
                            ::std::result::Result::Ok(val) => {
                                if !::anti_dbg::verify_sleep(#val_pow, #id_sleep) {
                                    #(#exit_hard_0)*
                                }
                                values.push(val);
                            },
                            ::std::result::Result::Err(_) => {
                                is_soft_err = true;
                            }
                        }
                    }

                    let dur_inst = #id_t_inst.elapsed().as_secs_f64() * 1000.0;
                    let dur_sys = #id_t_sys.elapsed().unwrap_or_default().as_secs_f64() * 1000.0;
                    let delta_probe = ::anti_dbg::probe().saturating_sub(#id_t_probe);

                    if dur_inst > 1.0 {
                        #(#checks_a)*
                    }

                    let mut elapseds = ::std::vec::Vec::with_capacity(values.len());
                    for val in &values {
                        // val_inst 代表子线程存活的总耗时
                        elapseds.push(#val_inst.saturating_duration_since(#id_t_inst).as_secs_f64() * 1000.0);
                    }

                    if !elapseds.is_empty() {
                        elapseds.sort_unstable_by(|a, b| a.total_cmp(b));
                        #(#checks_b)*
                    }

                    if #fn_record_ident(is_soft_err) {
                        #(#exit_soft)*
                    }
                }
            };

            let check = parse! { #check_stream };

            Some((init, check))
        },
        next,
    );

    injector.visit_block_mut(&mut func.block);
    quote!(#func)
}
