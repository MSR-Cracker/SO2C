"""End-to-end generation tests for the emitted .cpp/.h sources."""

import os
import tempfile

from so2c.generate_c import generate_c

from .conftest import REQUIRES_SAMPLE, LIB


@REQUIRES_SAMPLE
def test_generate_c_structure(analysis):
    with tempfile.TemporaryDirectory() as td:
        files = generate_c(analysis, os.path.join(td, "out"), "demo")
        paths = [p for p, _ in files]
        cpp = [p for p, _ in files if p.endswith(".cpp")][0]
        header = [p for p, _ in files if p.endswith(".h")][0]
        cpp_txt = open(cpp).read()
        header_txt = open(header).read()

    # header: one JNIEXPORT per exported JNI method
    n_export = len(analysis.jni_exports)
    assert header_txt.count("JNIEXPORT") == n_export

    # source: exactly the recovered internal order + forward declarations
    assert cpp_txt.count("static void sub_1050(void);") == 1
    assert cpp_txt.count("static void sub_1050(void) {") == 1
    assert cpp_txt.count("static void sub_1060(void);") == 1
    assert cpp_txt.count("static void sub_1084(void);") == 1
    assert "recovered from stripped .text" in cpp_txt

    # import forward declarations for the runtime glue we actually call
    assert "extern \"C\" void __cxa_finalize(void *dso_handle);" in cpp_txt
    assert "extern \"C\" void __stack_chk_fail(void);" in cpp_txt
    assert "extern \"C\" int __cxa_atexit" in cpp_txt


@REQUIRES_SAMPLE
def test_all_funcs_accounted(analysis):
    with tempfile.TemporaryDirectory() as td:
        generate_c(analysis, os.path.join(td, "out"), "demo")
        cpp = open(os.path.join(td, "out", "decompiled", "libmsr.so.cpp")).read()

    installed = []
    header_marker = "Internal functions recovered from .text"
    # every recovered internal function must have an emitted body
    for f in analysis.functions:
        if f.kind == "plt":
            continue
        name = f.short_name
        if f.kind == "exported":
            assert f"JNICALL {name}(" in cpp, name
        else:
            assert f"static void {name}(void);" in cpp, name
            assert f"static void {name}(void) {{" in cpp, name
            installed.append(name)
    assert len(installed) == 5
    assert header_marker in cpp


@REQUIRES_SAMPLE
def test_summary_includes_functions(analysis):
    import json
    from so2c.engine import write_summary
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        result = write_summary(analysis, td)
    funcs = result["functions"]
    kinds = {f["kind"] for f in funcs}
    assert "exported" in kinds and "internal" in kinds and "plt" in kinds
    nonplt = [f for f in funcs if f["kind"] != "plt"]
    assert len(nonplt) == 19
    addrs = sorted(f["address"] for f in nonplt)
    assert addrs[0] == 0x1050
    assert addrs[-1] == 0x184C
    # gap-free
    cursor = addrs[0]
    for a in addrs:
        assert a == cursor
        cursor = a + [f["size"] for f in nonplt if f["address"] == a][0]