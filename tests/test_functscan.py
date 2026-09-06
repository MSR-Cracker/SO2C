"""Function-boundary recovery on stripped .text binaries."""

from so2c.decompile.functscan import discover_functions, FuncInfo

from .conftest import REQUIRES_SAMPLE


@REQUIRES_SAMPLE
def test_discovers_expected_functions(analysis):
    funcs = discover_functions(analysis.elf, analysis.resolver)
    nonplt = [f for f in funcs if f.kind != "plt"]

    # 14 exported JNI methods + 5 internal helpers + 3 .plt stubs
    assert len(funcs) == 22
    assert len(nonplt) == 19

    exported = [f for f in nonplt if f.kind == "exported"]
    internal = [f for f in nonplt if f.kind == "internal"]
    assert len(exported) == 14
    assert len(internal) == 5

    internal_addrs = {f.addr for f in internal}
    assert internal_addrs == {0x1050, 0x1060, 0x1068, 0x1070, 0x1084}


@REQUIRES_SAMPLE
def test_sizes_match_elf_for_exports(analysis):
    sized = {e.addr: e.size for e in analysis.exports if e.size}
    funcs = {f.addr: f for f in discover_functions(analysis.elf,
                                                   analysis.resolver)}
    for addr, size in sized.items():
        assert addr in funcs, f"export 0x{addr:x} missing"
        assert funcs[addr].size == size, \
            f"export size mismatch for 0x{addr:x}"


@REQUIRES_SAMPLE
def test_gap_free_coverage_of_text(analysis):
    funcs = discover_functions(analysis.elf, analysis.resolver)
    nonplt = sorted((f for f in funcs if f.kind != "plt"), key=lambda f: f.addr)
    lo, hi = analysis.elf.text_range()
    assert nonplt[0].addr == lo
    assert nonplt[0].addr >= lo
    cursor = nonplt[0].addr
    for f in nonplt:
        assert f.addr >= cursor - 4, "overlapping functions"
        assert f.size > 0
    nxt = nonplt[0].addr
    for f in nonplt:
        assert f.addr == nxt, "gap in text coverage"
        nxt = f.addr + f.size
    assert nxt == hi


@REQUIRES_SAMPLE
def test_no_overlaps_and_4_alignment(analysis):
    funcs = sorted(discover_functions(analysis.elf, analysis.resolver),
                   key=lambda f: f.addr)
    for f in funcs:
        assert f.size > 0
    for a, b in zip(funcs, funcs[1:]):
        if a.kind == "plt" or b.kind == "plt":
            continue
        assert a.addr + a.size <= b.addr
    for f in funcs:
        assert f.addr % 4 == 0
        assert f.size % 4 == 0


@REQUIRES_SAMPLE
def test_plt_stubs_resolved(analysis):
    funcs = discover_functions(analysis.elf, analysis.resolver)
    plt = {f.addr: f.name for f in funcs if f.kind == "plt"}
    assert plt.get(0x1920) == "__cxa_finalize"
    assert plt.get(0x1930) == "__cxa_atexit"
    assert plt.get(0x1940) == "__stack_chk_fail"


def test_funcinfo_short_name_default():
    f = FuncInfo(addr=0x1234, size=8)
    assert f.short_name == "sub_1234"
    assert f.name == ""