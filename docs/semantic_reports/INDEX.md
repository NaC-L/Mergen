# Equivalence reports (original vs lifted)

Each report compares the **native binary** built from `testcases/rewrite_smoke/<name>` (linked through a small driver that calls the target symbol directly) against the **lifted+optimized LLVM IR** in `rewrite-regression-work/ir_outputs/<name>.ll` (executed via LLVM `lli`) on the manifest-declared input cases.

- **Samples:** 1/1 equivalent across all cases, 0 failing, 0 with no semantic cases
- **Cases:** 4/4 equivalent overall

Regenerate after a re-lift:

```
set CLANG_CL_EXE=C:\Program Files\LLVM\bin\clang-cl.exe
scripts\rewrite\run.cmd
python scripts\rewrite\generate_equivalence_reports.py
```

| Sample | Verdict | Cases | Report |
|--------|---------|-------|--------|
| calc_cout | PASS | 4/4 | [calc_cout_report.md](calc_cout_report.md) |
