/*
 * RISC-V translation routines for the RV64A Standard Extension.
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2018 Peer Adelt, peer.adelt@hni.uni-paderborn.de
 *                    Bastian Koppelmann, kbastian@mail.uni-paderborn.de
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

static bool gen_lr(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGv src1;
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 memop_v = tcg_constant_i32((int)mop);
    TCGv_i32 rd = tcg_constant_i32(a->rd);
    decode_save_opc(ctx);
    src1 = get_address(ctx, a->rs1, 0);
    if (a->rl) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_STRL);
    }
    tcg_gen_qemu_ld_tl(load_val, src1, ctx->mem_idx, mop);
    gen_helper_load_with_cap(cpu_env, src1, rs1, memop_v);
    if (a->aq) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_LDAQ);
    }

    /* Put addr in load_res, data in load_val.  */
    tcg_gen_mov_tl(load_res, src1);
    gen_set_gpr(ctx, a->rd, load_val);
    gen_helper_check_cap_load(cpu_env, src1, rd, tcg_constant_i32((int)mop));

    return true;
}

static bool gen_sc(DisasContext *ctx, arg_atomic *a, MemOp mop)
{
    TCGv dest, src1, src2;
    TCGLabel *l1 = gen_new_label();
    TCGLabel *l2 = gen_new_label();
    TCGLabel *l3 = gen_new_label();
    TCGv_i32 rs1 = tcg_constant_i32(a->rs1);
    TCGv_i32 rs2 = tcg_constant_i32(a->rs2);
    TCGv_i32 memop_v = tcg_constant_i32((int)mop);

    decode_save_opc(ctx);
    src1 = get_address(ctx, a->rs1, 0);
    tcg_gen_brcond_tl(TCG_COND_NE, load_res, src1, l1);

    /*
     * Note that the TCG atomic primitives are SC,
     * so we can ignore AQ/RL along this path.
     */
    dest = tcg_temp_new();
    src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    tcg_gen_atomic_cmpxchg_tl(dest, load_res, load_val, src2,
                              ctx->mem_idx, mop);
    tcg_gen_setcond_tl(TCG_COND_NE, dest, dest, load_val);
    tcg_gen_brcond_tl(TCG_COND_NE, dest, tcg_constant_i64(0), l3); // skips cap store
    gen_helper_store_with_cap(cpu_env, src1, rs1, rs2, memop_v, tcg_constant_i32(1));
    gen_set_label(l3);
    gen_set_gpr(ctx, a->rd, dest);
    tcg_gen_br(l2);

    gen_set_label(l1);
    /*
     * Address comparison failure.  However, we still need to
     * provide the memory barrier implied by AQ/RL.
     */
    tcg_gen_mb(TCG_MO_ALL + a->aq * TCG_BAR_LDAQ + a->rl * TCG_BAR_STRL);
    gen_set_gpr(ctx, a->rd, tcg_constant_tl(1));

    gen_set_label(l2);
    /*
     * Clear the load reservation, since an SC must fail if there is
     * an SC to any address, in between an LR and SC pair.
     */
    tcg_gen_movi_tl(load_res, -1);

    return true;
}

static bool gen_amo(DisasContext *ctx, arg_atomic *a,
                    void(*func)(TCGv, TCGv, TCGv, TCGArg, MemOp),
                    MemOp mop)
{
    TCGv dest = dest_gpr(ctx, a->rd);
    TCGv src1, src2 = get_gpr(ctx, a->rs2, EXT_NONE);

    decode_save_opc(ctx);
    src1 = get_address(ctx, a->rs1, 0);
    func(dest, src1, src2, ctx->mem_idx, mop);
    gen_helper_cap_scrub(cpu_env, src1);

    gen_set_gpr(ctx, a->rd, dest);
    return true;
}

static bool trans_lr_w(DisasContext *ctx, arg_lr_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_lr(ctx, a, (MO_ALIGN | MO_TESL));
}

static bool trans_sc_w(DisasContext *ctx, arg_sc_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_sc(ctx, a, (MO_ALIGN | MO_TESL));
}

static bool trans_amoswap_w(DisasContext *ctx, arg_amoswap_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoadd_w(DisasContext *ctx, arg_amoadd_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoxor_w(DisasContext *ctx, arg_amoxor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoand_w(DisasContext *ctx, arg_amoand_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amoor_w(DisasContext *ctx, arg_amoor_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomin_w(DisasContext *ctx, arg_amomin_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomax_w(DisasContext *ctx, arg_amomax_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amominu_w(DisasContext *ctx, arg_amominu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_amomaxu_w(DisasContext *ctx, arg_amomaxu_w *a)
{
    REQUIRE_EXT(ctx, RVA);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TESL));
}

static bool trans_lr_d(DisasContext *ctx, arg_lr_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_lr(ctx, a, MO_ALIGN | MO_TEUQ);
}

static bool trans_sc_d(DisasContext *ctx, arg_sc_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_sc(ctx, a, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amoswap_d(DisasContext *ctx, arg_amoswap_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_xchg_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amoadd_d(DisasContext *ctx, arg_amoadd_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_add_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amoxor_d(DisasContext *ctx, arg_amoxor_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_xor_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amoand_d(DisasContext *ctx, arg_amoand_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_and_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amoor_d(DisasContext *ctx, arg_amoor_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_or_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amomin_d(DisasContext *ctx, arg_amomin_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smin_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amomax_d(DisasContext *ctx, arg_amomax_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_smax_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amominu_d(DisasContext *ctx, arg_amominu_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umin_tl, (MO_ALIGN | MO_TEUQ));
}

static bool trans_amomaxu_d(DisasContext *ctx, arg_amomaxu_d *a)
{
    REQUIRE_64BIT(ctx);
    return gen_amo(ctx, a, &tcg_gen_atomic_fetch_umax_tl, (MO_ALIGN | MO_TEUQ));
}
