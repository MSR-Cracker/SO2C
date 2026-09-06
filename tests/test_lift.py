"""Unit tests for the AArch64 lifting engine's value tracking."""

from so2c.decompile import expr as E
from so2c.decompile.lift import (
    _cond_operator, _is_store, _aarch64_simple_cond,
)

from .conftest import REQUIRES_SAMPLE


def test_store_detection():
    assert _is_store("str")
    assert _is_store("stur")
    assert _is_store("strb")
    assert _is_store("stp")     # was previously mistaken for a load
    assert _is_store("stnp")
    assert not _is_store("ldr")
    assert not _is_store("ldp")
    assert not _is_store("ldur")


def test_cond_operator_mapping():
    assert _cond_operator("eq") == "=="
    assert _cond_operator("ne") == "!="
    assert _cond_operator("gt") == ">"
    assert _cond_operator("ge") == ">="
    assert _cond_operator("lt") == "<"
    assert _cond_operator("le") == "<="
    assert _cond_operator("al") is None


def test_simple_cond_fallback():
    assert _aarch64_simple_cond("ne") == "(flags NE)"
    assert _aarch64_simple_cond("hi") == "(flags HI)"


def test_addr_of_imm_renders_as_cast():
    # adr x0, #0x5950  must not become the invalid C "&(0x5950)"
    assert E.render(E.addr_of(E.imm(0x5950))) == "(void*)0x5950"
    assert E.render(E.addr_of(E.imm(0))) == "(void*)0"
    v = E.var("x")
    assert E.render(E.addr_of(v)) == "&x"


def test_const_renders_as_c_literal():
    assert E.render(E.imm(0x1234_5678)) == "305419896"   # < 2^31 -> decimal
    assert E.render(E.imm(0x8000_0000)) == "0x80000000"  # >= 2^31 -> hex
    assert E.render(E.imm(-4)) == "-0x4"
    assert E.render(E.imm(0)) == "0"


@REQUIRES_SAMPLE
def test_decompile_internal_string_helper(analysis):
    from so2c.decompile.arm64 import decompile_function
    from so2c.generate_c import _build_str_index
    str_idx = _build_str_index(analysis)
    lines = decompile_function(analysis.elf, analysis.resolver, str_idx, 0x10A0,
                               0x20, "Java_com_dex2c_NativeStrings_get",
                               func_names={}, entry_env=True)
    body = "\n".join(lines)
    assert "NewStringUTF" in body
    assert "Welcome Shadow" in body


@REQUIRES_SAMPLE
def test_canary_prelude_and_epilogue(analysis):
    from so2c.decompile.arm64 import decompile_function
    lines = decompile_function(
        analysis.elf, analysis.resolver, {}, 0x10C0, 172,
        "Java_com_test1_MainActivity_getCheckedItemPositionsToArray__"
        "Landroid_widget_ListView_2",
        func_names={}, entry_env=True)
    body = "\n".join(lines)
    assert "uintptr_t canary;" in body
    assert "extern uintptr_t __stack_chk_guard;" in body
    assert "__stack_chk_guard != canary" in body
    assert "__stack_chk_fail();" in body


@REQUIRES_SAMPLE
def test_jvalue_args_array_assembled(analysis):
    from so2c.decompile.arm64 import decompile_function
    lines = decompile_function(
        analysis.elf, analysis.resolver, {}, 0x10C0, 172,
        "Java_com_test1_MainActivity_getCheckedItemPositionsToArray__"
        "Landroid_widget_ListView_2",
        func_names={}, entry_env=True)
    body = "\n".join(lines)
    assert "jvalue args[1];" in body
    assert "args[0].l = a;" in body


@REQUIRES_SAMPLE
def test_internal_stub_surfaces_import_tail(analysis):
    from so2c.decompile.arm64 import decompile_function
    func_names = {0x1050: "sub_1050", 0x1060: "sub_1060"}
    lines = decompile_function(analysis.elf, analysis.resolver, {}, 0x1050, 16,
                               "sub_1050", func_names=func_names,
                               entry_env=False)
    body = "\n".join(lines)
    assert "__cxa_finalize((void*)0x5950);" in body
    assert "// tail call" in body