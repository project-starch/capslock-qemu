// TODO: Pure emulation-based implementation; improve the performance

static bool trans_csmovc(DisasContext *ctx, arg_csmovc *a) {
    // just a nop for now
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csmovc(cpu_env, rd, rs1);
    return true;
}

static bool trans_cscincoffset(DisasContext *ctx, arg_cscincoffset *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_cscincoffset(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_cscincoffsetimm(DisasContext *ctx, arg_cscincoffsetimm *a) {
    TCGv imm = tcg_constant_tl(a->imm); // TODO: sign extending
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_cscincoffsetimm(cpu_env, rd, rs1, imm);
    return true;
}

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

static bool trans_csshrink(DisasContext *ctx, arg_csshrink *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csshrink(cpu_env, rd, rs1, rs2);
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