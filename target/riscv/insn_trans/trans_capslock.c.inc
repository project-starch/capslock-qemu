static bool trans_csscc(DisasContext *ctx, arg_csscc *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csscc(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_cslcc(DisasContext *ctx, arg_cslcc *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 imm = tcg_constant_i32(a->rs2);
    gen_helper_cslcc(cpu_env, rd, rs1, imm);
    return true;
}

static bool trans_csdebuggencap(DisasContext *ctx, arg_csdebuggencap *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv rs1_v = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv rs2_v = get_gpr(ctx, a->rs2, EXT_NONE);

    gen_helper_csdebuggencap(cpu_env, rd, rs1_v, rs2_v);
    return true;
}

static bool trans_csrevoke(DisasContext *ctx, arg_csrevoke *a) {
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csrevoke(cpu_env, rs1);
    return true;
}

static bool trans_csborrow(DisasContext *ctx, arg_csborrow *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csborrow(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_csborrowmut(DisasContext *ctx, arg_csborrowmut *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csborrowmut(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_csmarkunsafecell(DisasContext *ctx, arg_csmarkunsafecell *a) {
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csmarkunsafecell(cpu_env, rs1, rs2);
    return true;
}

static bool trans_csshrink(DisasContext *ctx, arg_csshrink *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csshrink(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_csshrinkto(DisasContext *ctx, arg_csshrinkto *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv imm = tcg_constant_tl(a->imm);
    gen_helper_csshrinkto(cpu_env, rd, rs1, imm);
    return true;
}

static bool trans_cssplit(DisasContext *ctx, arg_cssplit *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_cssplit(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_cstighten(DisasContext *ctx, arg_cstighten *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 imm = tcg_constant_i32(a->rs2);
    gen_helper_cstighten(cpu_env, rd, rs1, imm);
    return true;
}

static bool trans_csloadsp(DisasContext *ctx, arg_csloadsp *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csloadsp(cpu_env, rd, rs1);
    return true;
}

static bool trans_csgencapstack(DisasContext *ctx, arg_csgencapstack *a) {
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv imm = tcg_constant_tl(a->imm);
    gen_helper_csgencapstack(cpu_env, rs1, imm);
    return true;
}

static bool trans_csdrop(DisasContext *ctx, arg_csdrop *a) {
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csdrop(cpu_env, rs1);
    return true;
}

/* CapsLock debug instructions */

static bool trans_csdebugprint(DisasContext *ctx, arg_csdebugprint *a) {
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csdebugprint(cpu_env, rs1);
    return true;
}

static bool trans_csdebugbreak(DisasContext *ctx, arg_csdebugbreak *a) {
    gen_helper_capslock_debugger(cpu_env, tcg_constant_tl(0));
    return true;
}

static bool trans_csdebugcount(DisasContext *ctx, arg_csdebugcount *a) {
    TCGv rs1_v = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv rs2_v = get_gpr(ctx, a->rs2, EXT_NONE);
    gen_helper_csdebugcount(cpu_env, rs1_v, rs2_v);
    return true;
}

static bool trans_csdebugcountprint(DisasContext *ctx, arg_csdebugcountprint *a) {
    gen_helper_csdebugcountprint(cpu_env);
    return true;
}
