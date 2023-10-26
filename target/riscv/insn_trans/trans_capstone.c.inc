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

static bool trans_csdelin(DisasContext *ctx, arg_csdelin *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    gen_helper_csdelin(cpu_env, rd);
    return true;
}

static bool trans_csinit(DisasContext *ctx, arg_csinit *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    gen_helper_csinit(cpu_env, rd, rs1, rs2);
    return true;
}

static bool trans_csseal(DisasContext *ctx, arg_csseal *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csseal(cpu_env, rd, rs1);
    return true;
}

static bool trans_csccsrrw(DisasContext *ctx, arg_csccsrrw *a) {
    TCGv imm = tcg_constant_tl(a->imm);
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    gen_helper_csccsrrw(cpu_env, rd, rs1, imm);
    return true;
}

static bool trans_csdebuggencap(DisasContext *ctx, arg_csdebuggencap *a) {
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    TCGv rs1_v = get_gpr(ctx, a->rs1, EXT_NONE);
    TCGv rs2_v = get_gpr(ctx, a->rs2, EXT_NONE);

    gen_helper_csdebuggencap(cpu_env, rd, rs1_v, rs2_v);
    return true;
}

static bool trans_csdebugoncapmem(DisasContext *ctx, arg_csdebugoncapmem *a) {
    TCGv rs1_v = get_gpr(ctx, a->rs1, EXT_NONE);
    gen_helper_csdebugoncapmem(cpu_env, rs1_v);
    decode_save_opc(ctx);
    gen_update_pc(ctx, ctx->cur_insn_len);
    exit_tb(ctx);
    ctx->base.is_jmp = DISAS_NORETURN;
    return true;
}

static bool trans_csldc(DisasContext *ctx, arg_csldc *a) {
    /* Can only be used in cap-mem mode */
    if (ctx->cap_mem && ctx->priv == PRV_U) {
        TCGv addr = tcg_temp_new();
        TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
        TCGv_i32 rd = tcg_constant_i32(a->rd);
        TCGv imm = tcg_constant_tl(a->imm);
        TCGv_i32 memop_v = tcg_constant_i32((int)MO_TEUO);

        gen_helper_load_with_cap(addr, cpu_env, rs1, imm, memop_v);

        TCGv dest1 = tcg_temp_new();
        TCGv dest2 = tcg_temp_new();

        tcg_gen_qemu_ld_tl(dest1, addr, ctx->mem_idx, MO_TESQ);
        tcg_gen_addi_tl(addr, addr, 8);
        tcg_gen_qemu_ld_tl(dest2, addr, ctx->mem_idx, MO_TESQ);

        gen_helper_reg_set_cap_compressed(cpu_env, rd, dest1, dest2); // TODO: this can be optimised
    } else {
        gen_exception_illegal(ctx);
    }
    return true;
}


static bool trans_csstc(DisasContext *ctx, arg_csstc *a) {
    // TODO: implement
    assert(false);
    return true;
}
