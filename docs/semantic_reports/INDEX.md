# Semantic equivalence reports

One report per non-skipped sample under `testcases/rewrite_smoke/`. Each report compares the manifest's declared semantic cases against the lifted+optimized IR by executing the IR via LLVM `lli` and asserting the return value.

- **Samples:** 96/97 fully pass, 0 failing, 1 with no semantic cases
- **Cases:** 849/849 pass overall

Regenerate with `python scripts/rewrite/generate_semantic_reports.py` after rerunning the lifter (`scripts\rewrite\run.cmd` or `python test.py quick`) so `ir_outputs/*.ll` is fresh.

| Sample | Verdict | Cases | Report |
|--------|---------|-------|--------|
| bitchain | PASS | 1/1 | [bitchain.md](bitchain.md) |
| branch | PASS | 5/5 | [branch.md](branch.md) |
| bytecode_vm_loop | PASS | 6/6 | [bytecode_vm_loop.md](bytecode_vm_loop.md) |
| calc_cout | PASS | 4/4 | [calc_cout.md](calc_cout.md) |
| calc_fib | PASS | 1/1 | [calc_fib.md](calc_fib.md) |
| calc_grade | PASS | 11/11 | [calc_grade.md](calc_grade.md) |
| calc_jumptable | PASS | 12/12 | [calc_jumptable.md](calc_jumptable.md) |
| calc_jumptable_large | PASS | 10/10 | [calc_jumptable_large.md](calc_jumptable_large.md) |
| calc_mixed | PASS | 7/7 | [calc_mixed.md](calc_mixed.md) |
| calc_sum_array | PASS | 1/1 | [calc_sum_array.md](calc_sum_array.md) |
| calc_sum_to_n | PASS | 6/6 | [calc_sum_to_n.md](calc_sum_to_n.md) |
| calc_switch | PASS | 8/8 | [calc_switch.md](calc_switch.md) |
| cmov_chain | PASS | 5/5 | [cmov_chain.md](cmov_chain.md) |
| diamond | PASS | 8/8 | [diamond.md](diamond.md) |
| dummy_vm_loop | PASS | 6/6 | [dummy_vm_loop.md](dummy_vm_loop.md) |
| indirect | PASS | 1/1 | [indirect.md](indirect.md) |
| instr_add | PASS | 1/1 | [instr_add.md](instr_add.md) |
| instr_rol | PASS | 1/1 | [instr_rol.md](instr_rol.md) |
| instr_sub | PASS | 1/1 | [instr_sub.md](instr_sub.md) |
| instr_xor | PASS | 1/1 | [instr_xor.md](instr_xor.md) |
| jumptable_basic | PASS | 6/6 | [jumptable_basic.md](jumptable_basic.md) |
| jumptable_computation | PASS | 7/7 | [jumptable_computation.md](jumptable_computation.md) |
| jumptable_dense | PASS | 10/10 | [jumptable_dense.md](jumptable_dense.md) |
| jumptable_rel32 | PASS | 7/7 | [jumptable_rel32.md](jumptable_rel32.md) |
| jumptable_shared_targets | PASS | 8/8 | [jumptable_shared_targets.md](jumptable_shared_targets.md) |
| jumptable_shifted | PASS | 9/9 | [jumptable_shifted.md](jumptable_shifted.md) |
| loop_simple | PASS | 1/1 | [loop_simple.md](loop_simple.md) |
| multi_arg | PASS | 5/5 | [multi_arg.md](multi_arg.md) |
| nested_branch | PASS | 8/8 | [nested_branch.md](nested_branch.md) |
| stack | PASS | 1/1 | [stack.md](stack.md) |
| stack_vm_loop | PASS | 6/6 | [stack_vm_loop.md](stack_vm_loop.md) |
| switch_3way | PASS | 6/6 | [switch_3way.md](switch_3way.md) |
| switch_sparse | PASS | 7/7 | [switch_sparse.md](switch_sparse.md) |
| vm_4state_loop | PASS | 11/11 | [vm_4state_loop.md](vm_4state_loop.md) |
| vm_abs_array_loop | PASS | 11/11 | [vm_abs_array_loop.md](vm_abs_array_loop.md) |
| vm_argmax_loop | PASS | 11/11 | [vm_argmax_loop.md](vm_argmax_loop.md) |
| vm_bitreverse_loop | PASS | 10/10 | [vm_bitreverse_loop.md](vm_bitreverse_loop.md) |
| vm_bittransitions_loop | PASS | 11/11 | [vm_bittransitions_loop.md](vm_bittransitions_loop.md) |
| vm_branchy_loop | PASS | 8/8 | [vm_branchy_loop.md](vm_branchy_loop.md) |
| vm_ca_loop | PASS | 12/12 | [vm_ca_loop.md](vm_ca_loop.md) |
| vm_caesar_loop | PASS | 12/12 | [vm_caesar_loop.md](vm_caesar_loop.md) |
| vm_carrychain_loop | PASS | 11/11 | [vm_carrychain_loop.md](vm_carrychain_loop.md) |
| vm_classify_loop | PASS | 10/10 | [vm_classify_loop.md](vm_classify_loop.md) |
| vm_collatz_loop | PASS | 8/8 | [vm_collatz_loop.md](vm_collatz_loop.md) |
| vm_countdown_loop | PASS | 8/8 | [vm_countdown_loop.md](vm_countdown_loop.md) |
| vm_ctz_loop | PASS | 12/12 | [vm_ctz_loop.md](vm_ctz_loop.md) |
| vm_digitsum_loop | PASS | 12/12 | [vm_digitsum_loop.md](vm_digitsum_loop.md) |
| vm_dispatch_table_loop | PASS | 10/10 | [vm_dispatch_table_loop.md](vm_dispatch_table_loop.md) |
| vm_djb2_loop | PASS | 12/12 | [vm_djb2_loop.md](vm_djb2_loop.md) |
| vm_dual_counter_loop | PASS | 8/8 | [vm_dual_counter_loop.md](vm_dual_counter_loop.md) |
| vm_dupcount_loop | PASS | 11/11 | [vm_dupcount_loop.md](vm_dupcount_loop.md) |
| vm_factorial_loop | PASS | 10/10 | [vm_factorial_loop.md](vm_factorial_loop.md) |
| vm_fibonacci_loop | PASS | 10/10 | [vm_fibonacci_loop.md](vm_fibonacci_loop.md) |
| vm_find2max_loop | PASS | 11/11 | [vm_find2max_loop.md](vm_find2max_loop.md) |
| vm_gcd_loop | PASS | 8/8 | [vm_gcd_loop.md](vm_gcd_loop.md) |
| vm_geometric_loop | PASS | 10/10 | [vm_geometric_loop.md](vm_geometric_loop.md) |
| vm_hamming_loop | PASS | 10/10 | [vm_hamming_loop.md](vm_hamming_loop.md) |
| vm_hexcount_loop | PASS | 12/12 | [vm_hexcount_loop.md](vm_hexcount_loop.md) |
| vm_horner_signed_loop | PASS | 10/10 | [vm_horner_signed_loop.md](vm_horner_signed_loop.md) |
| vm_imported_abs_loop | PASS | 10/10 | [vm_imported_abs_loop.md](vm_imported_abs_loop.md) |
| vm_imported_bswap_loop | PASS | 11/11 | [vm_imported_bswap_loop.md](vm_imported_bswap_loop.md) |
| vm_imported_clz_loop | PASS | 10/10 | [vm_imported_clz_loop.md](vm_imported_clz_loop.md) |
| vm_imported_cttz_loop | PASS | 11/11 | [vm_imported_cttz_loop.md](vm_imported_cttz_loop.md) |
| vm_imported_popcnt_loop | PASS | 10/10 | [vm_imported_popcnt_loop.md](vm_imported_popcnt_loop.md) |
| vm_imported_rotl_loop | PASS | 10/10 | [vm_imported_rotl_loop.md](vm_imported_rotl_loop.md) |
| vm_isqrt_loop | PASS | 15/15 | [vm_isqrt_loop.md](vm_isqrt_loop.md) |
| vm_kernighan_loop | PASS | 12/12 | [vm_kernighan_loop.md](vm_kernighan_loop.md) |
| vm_lcg_loop | PASS | 10/10 | [vm_lcg_loop.md](vm_lcg_loop.md) |
| vm_lfsr_loop | PASS | 10/10 | [vm_lfsr_loop.md](vm_lfsr_loop.md) |
| vm_minabs_loop | PASS | 11/11 | [vm_minabs_loop.md](vm_minabs_loop.md) |
| vm_minarray_loop | PASS | 12/12 | [vm_minarray_loop.md](vm_minarray_loop.md) |
| vm_modcounter_loop | PASS | 11/11 | [vm_modcounter_loop.md](vm_modcounter_loop.md) |
| vm_nested_abs_loop | PASS | 11/11 | [vm_nested_abs_loop.md](vm_nested_abs_loop.md) |
| vm_nested_loop | PASS | 10/10 | [vm_nested_loop.md](vm_nested_loop.md) |
| vm_outlined_wrapper_loop | **NA** | 0/0 | [vm_outlined_wrapper_loop.md](vm_outlined_wrapper_loop.md) |
| vm_palindrome_loop | PASS | 14/14 | [vm_palindrome_loop.md](vm_palindrome_loop.md) |
| vm_pcg_loop | PASS | 12/12 | [vm_pcg_loop.md](vm_pcg_loop.md) |
| vm_piecewise_loop | PASS | 11/11 | [vm_piecewise_loop.md](vm_piecewise_loop.md) |
| vm_polynomial_loop | PASS | 10/10 | [vm_polynomial_loop.md](vm_polynomial_loop.md) |
| vm_popcount_loop | PASS | 10/10 | [vm_popcount_loop.md](vm_popcount_loop.md) |
| vm_power_loop | PASS | 10/10 | [vm_power_loop.md](vm_power_loop.md) |
| vm_powermod_loop | PASS | 11/11 | [vm_powermod_loop.md](vm_powermod_loop.md) |
| vm_prefix_sum_loop | PASS | 11/11 | [vm_prefix_sum_loop.md](vm_prefix_sum_loop.md) |
| vm_prefix_xor_loop | PASS | 11/11 | [vm_prefix_xor_loop.md](vm_prefix_xor_loop.md) |
| vm_register_loop | PASS | 10/10 | [vm_register_loop.md](vm_register_loop.md) |
| vm_rotate_loop | PASS | 10/10 | [vm_rotate_loop.md](vm_rotate_loop.md) |
| vm_runlength_loop | PASS | 13/13 | [vm_runlength_loop.md](vm_runlength_loop.md) |
| vm_runlmax_loop | PASS | 12/12 | [vm_runlmax_loop.md](vm_runlmax_loop.md) |
| vm_saturating_loop | PASS | 10/10 | [vm_saturating_loop.md](vm_saturating_loop.md) |
| vm_search_loop | PASS | 10/10 | [vm_search_loop.md](vm_search_loop.md) |
| vm_shiftmul_loop | PASS | 11/11 | [vm_shiftmul_loop.md](vm_shiftmul_loop.md) |
| vm_skiploop_loop | PASS | 11/11 | [vm_skiploop_loop.md](vm_skiploop_loop.md) |
| vm_stride_loop | PASS | 12/12 | [vm_stride_loop.md](vm_stride_loop.md) |
| vm_window_loop | PASS | 11/11 | [vm_window_loop.md](vm_window_loop.md) |
| vm_xor_accumulator_loop | PASS | 8/8 | [vm_xor_accumulator_loop.md](vm_xor_accumulator_loop.md) |
| vm_xordecrypt_loop | PASS | 10/10 | [vm_xordecrypt_loop.md](vm_xordecrypt_loop.md) |
| vm_zigzag_loop | PASS | 11/11 | [vm_zigzag_loop.md](vm_zigzag_loop.md) |
