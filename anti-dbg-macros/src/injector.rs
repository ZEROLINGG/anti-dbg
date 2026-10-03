// anti-dbg/macros/src/injector.rs
use syn::visit_mut::{self, VisitMut};
use syn::{Block, Expr, ExprForLoop, ExprLoop, ExprWhile, Stmt};
pub struct StatementInjector<I, N, G> {
    allow_loop: bool,
    loop_depth: u64,

    max_depth: Option<u64>,
    current_depth: u64,

    max_insertions: Option<u64>,
    insert_count: u64,

    insert_fn: I,
    next_id_fn: N,

    insert_ginit_fn: G,
    has_injected_ginit: bool,
}

impl<I, N, G> StatementInjector<I, N, G>
where
    I: FnMut(u64, &Stmt) -> Option<Vec<Stmt>>,
    N: FnMut() -> u64,
    G: FnMut() -> Option<Vec<Stmt>>,
{
    pub fn new(
        allow_loop: bool,
        max_depth: Option<u64>,
        max_insertions: Option<u64>,
        insert_ginit_fn: G,
        insert_fn: I,
        next_id_fn: N,
    ) -> Self {
        Self {
            allow_loop,
            loop_depth: 0,
            max_depth,
            current_depth: 0,
            max_insertions,
            insert_count: 0,
            insert_fn,
            next_id_fn,
            insert_ginit_fn,
            has_injected_ginit: false,
        }
    }
}

impl<I, N, G> VisitMut for StatementInjector<I, N, G>
where
    I: FnMut(u64, &Stmt) -> Option<Vec<Stmt>>,
    N: FnMut() -> u64,
    G: FnMut() -> Option<Vec<Stmt>>,
{
    fn visit_block_mut(&mut self, block: &mut Block) {
        self.current_depth += 1;

        visit_mut::visit_block_mut(self, block);

        let is_within_depth = self.max_depth.is_none_or(|max| self.current_depth <= max);
        let can_inject = is_within_depth && (self.loop_depth == 0 || self.allow_loop);
        let reached_max = self
            .max_insertions
            .is_some_and(|max| self.insert_count >= max);

        if (can_inject && !reached_max) || (self.current_depth == 1 && !self.has_injected_ginit) {
            let mut new_stmts = Vec::with_capacity(block.stmts.len() * 2 + 5);

            if self.current_depth == 1 && !self.has_injected_ginit {
                if let Some(ginit_stmts) = (self.insert_ginit_fn)() {
                    new_stmts.extend(ginit_stmts);
                }
                self.has_injected_ginit = true;
            }

            // 处理普通语句级别的注入
            for stmt in block.stmts.drain(..) {
                let can_insert_now = can_inject
                    && self
                        .max_insertions
                        .is_none_or(|max| self.insert_count < max);

                if can_insert_now {
                    let id = (self.next_id_fn)();
                    if let Some(new_stmts_to_inject) = (self.insert_fn)(id, &stmt) {
                        new_stmts.extend(new_stmts_to_inject);
                        self.insert_count += 1;
                    }
                }
                new_stmts.push(stmt);
            }

            block.stmts = new_stmts;
        }

        self.current_depth -= 1;
    }

    fn visit_expr_const_mut(&mut self, _node: &mut syn::ExprConst) {}
    fn visit_expr_for_loop_mut(&mut self, node: &mut ExprForLoop) {
        self.loop_depth += 1;
        visit_mut::visit_expr_for_loop_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_expr_loop_mut(&mut self, node: &mut ExprLoop) {
        self.loop_depth += 1;
        visit_mut::visit_expr_loop_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_expr_while_mut(&mut self, node: &mut ExprWhile) {
        self.loop_depth += 1;
        visit_mut::visit_expr_while_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_impl_item_const_mut(&mut self, _node: &mut syn::ImplItemConst) {}
    fn visit_item_const_mut(&mut self, _node: &mut syn::ItemConst) {}
    fn visit_item_static_mut(&mut self, _node: &mut syn::ItemStatic) {}
    fn visit_trait_item_const_mut(&mut self, _node: &mut syn::TraitItemConst) {}
}

pub struct PairStatementInjector<I, N, G> {
    allow_loop: bool,
    loop_depth: u64,
    max_depth: Option<u64>,
    current_depth: u64,
    max_insertions: Option<u64>,
    insert_count: u64,
    inserts_fn: I,
    next_id_fn: N,

    insert_ginit_fn: G,
    has_injected_ginit: bool,
}

impl<I, N, G> PairStatementInjector<I, N, G>
where
    I: FnMut(u64, &Stmt) -> Option<(Vec<Stmt>, Vec<Stmt>)>,
    N: FnMut() -> u64,
    G: FnMut() -> Option<Vec<Stmt>>,
{
    pub fn new(
        allow_loop: bool,
        max_depth: Option<u64>,
        max_insertions: Option<u64>,
        insert_ginit_fn: G,
        inserts_fn: I,
        next_id_fn: N,
    ) -> Self {
        Self {
            allow_loop,
            loop_depth: 0,
            max_depth,
            current_depth: 0,
            max_insertions,
            insert_count: 0,
            inserts_fn,
            next_id_fn,
            insert_ginit_fn,
            has_injected_ginit: false,
        }
    }

    fn is_terminal_expr(expr: &Expr) -> bool {
        matches!(
            expr,
            Expr::Break(_) | Expr::Continue(_) | Expr::Return(_) | Expr::Try(_)
        )
    }
}

impl<I, N, G> VisitMut for PairStatementInjector<I, N, G>
where
    I: FnMut(u64, &Stmt) -> Option<(Vec<Stmt>, Vec<Stmt>)>,
    N: FnMut() -> u64,
    G: FnMut() -> Option<Vec<Stmt>>,
{
    fn visit_block_mut(&mut self, block: &mut Block) {
        self.current_depth += 1;

        let old_stmts = std::mem::take(&mut block.stmts);
        let len = old_stmts.len();
        let mut new_stmts = Vec::with_capacity(len * 3 + 5);

        // --- 全局初始化注入逻辑：放在整个函数的首部 ---
        if self.current_depth == 1 && !self.has_injected_ginit {
            if let Some(ginit_stmts) = (self.insert_ginit_fn)() {
                new_stmts.extend(ginit_stmts);
            }
            self.has_injected_ginit = true;
        }

        for (i, mut stmt) in old_stmts.into_iter().enumerate() {
            let is_last = i == len - 1;

            // 优先递归处理内部结构（深度优先）
            visit_mut::visit_stmt_mut(self, &mut stmt);

            let is_within_depth = self.max_depth.is_none_or(|max| self.current_depth <= max);
            let can_inject = is_within_depth && (self.loop_depth == 0 || self.allow_loop);
            let reached_max = self
                .max_insertions
                .is_some_and(|max| self.insert_count >= max);

            if !can_inject || reached_max {
                new_stmts.push(stmt);
                continue;
            }

            let id = (self.next_id_fn)();
            if let Some((a_stmts, b_stmts)) = (self.inserts_fn)(id, &stmt) {
                match stmt {
                    Stmt::Expr(expr, semi) => {
                        if Self::is_terminal_expr(&expr) {
                            new_stmts.push(Stmt::Expr(expr, semi));
                        } else if semi.is_none() && is_last {
                            let res_ident = quote::format_ident!("__tmp_res_tail_{}", id);
                            let let_stmt: Stmt = syn::parse_quote! { let #res_ident = #expr; };
                            let ret_expr: Expr = syn::parse_quote! { #res_ident };
                            let ret_stmt = Stmt::Expr(ret_expr, None);

                            new_stmts.extend(a_stmts);
                            new_stmts.push(let_stmt);
                            new_stmts.extend(b_stmts);
                            new_stmts.push(ret_stmt);
                        } else {
                            new_stmts.extend(a_stmts);
                            new_stmts.push(Stmt::Expr(expr, semi));
                            new_stmts.extend(b_stmts);
                        }
                    }
                    Stmt::Item(item) => {
                        new_stmts.push(Stmt::Item(item));
                    }
                    _ => {
                        new_stmts.extend(a_stmts);
                        new_stmts.push(stmt);
                        new_stmts.extend(b_stmts);
                    }
                }
                self.insert_count += 1;
            } else {
                new_stmts.push(stmt);
            }
        }

        block.stmts = new_stmts;
        self.current_depth -= 1;
    }

    fn visit_expr_const_mut(&mut self, _node: &mut syn::ExprConst) {}
    fn visit_expr_for_loop_mut(&mut self, node: &mut ExprForLoop) {
        self.loop_depth += 1;
        visit_mut::visit_expr_for_loop_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_expr_loop_mut(&mut self, node: &mut ExprLoop) {
        self.loop_depth += 1;
        visit_mut::visit_expr_loop_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_expr_while_mut(&mut self, node: &mut ExprWhile) {
        self.loop_depth += 1;
        visit_mut::visit_expr_while_mut(self, node);
        self.loop_depth -= 1;
    }
    fn visit_impl_item_const_mut(&mut self, _node: &mut syn::ImplItemConst) {}
    fn visit_item_const_mut(&mut self, _node: &mut syn::ItemConst) {}
    fn visit_item_static_mut(&mut self, _node: &mut syn::ItemStatic) {}
    fn visit_trait_item_const_mut(&mut self, _node: &mut syn::TraitItemConst) {}
}
