#!/usr/bin/env python3

import os, shutil, subprocess, sys, glob
from common import run_cmd
from benchmark import SLICE_TARGETS

SPARROW_PATH = os.path.join('/sparrow', 'bin', 'sparrow')
TOTAL_NODES_TOK = '# DUG nodes  : '
SLICED_NODES_TOK = '# Sliced nodes : '
TOTAL_LINES_TOK = '# DUG lines  : '
SLICED_LINES_TOK = '# Sliced lines : '
SLICED_FUNS_TOK = '# Sliced funcs : '
RESULT = [[
    'target', 'poc', 'total_nodes', 'sliced_nodes', 'total_lines',
    'sliced_lines', 'sliced_functions'
]]

def setup_global(name):
    global BASE_DIR, SMAKE_OUT_DIR, SPARROW_OUT_DIR, TARG_LOC_DIR, DAFL_INPUT_DIR, DAFL_NAIVE_INPUT_DIR

    BASE_DIR = os.path.join('/projects', name)
    SMAKE_OUT_DIR = os.path.join(BASE_DIR, "smake")
    SPARROW_OUT_DIR = os.path.join(BASE_DIR, "sparrow")
    TARG_LOC_DIR = os.path.join(BASE_DIR, "line")
    DAFL_INPUT_DIR = os.path.join(BASE_DIR, "DAFL-input")
    DAFL_NAIVE_INPUT_DIR = os.path.join(BASE_DIR, "DAFL-input-naive")

def read_file(filename):
    f = open(filename, "r")
    buf = f.read().strip()
    f.close()
    return buf

def run_sparrow(benchmark, thin):
    input_dir = os.path.join(SMAKE_OUT_DIR)
    input_files = glob.glob(input_dir + '/*.i')

    out_dir = os.path.join(SPARROW_OUT_DIR)
    shutil.rmtree(out_dir, ignore_errors=True)
    os.makedirs(out_dir)
    cmd=[
        SPARROW_PATH, "-outdir", out_dir,
        "-frontend", SLICE_TARGETS[benchmark]['frontend'],
        "-unsound_alloc",
        "-unsound_const_string",
        "-unsound_recursion",
        "-unsound_noreturn_function",
        "-unsound_skip_global_array_init", "1000",
        "-skip_main_analysis", "-cut_cyclic_call",
        "-unwrap_alloc",
        "-entry_point", SLICE_TARGETS[benchmark]['entry_point'],
        "-max_pre_iter", "10"
    ]
    
    if thin:
        INPUT_DIR = DAFL_INPUT_DIR
    else:
        INPUT_DIR = DAFL_NAIVE_INPUT_DIR
        cmd += ["-full_slice"]

    bugs = SLICE_TARGETS[benchmark]['bugs']
    for bug in bugs:
        if os.path.exists(os.path.join(TARG_LOC_DIR, bug+".sparrow")):
            slice_loc = read_file(os.path.join(TARG_LOC_DIR, bug+".sparrow"))
        else:
            slice_loc = read_file(os.path.join(TARG_LOC_DIR, bug))
        cmd += ["-slice", bug + "=" + slice_loc]
    if 'additional_opt' in SLICE_TARGETS[benchmark]:
        cmd += SLICE_TARGETS[benchmark]['additional_opt']
    cmd += input_files

    run_sparrow = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    proc = {
        "prog": benchmark,
        "bugs": bugs,
        "p": run_sparrow,
        "outdir": out_dir
    }

    proc["p"].communicate()

    for bug in proc["bugs"]:
        # First, copy instrumentation target file.
        dst_dir = os.path.join(INPUT_DIR, "inst-targ")
        os.makedirs(dst_dir, exist_ok=True)
        inst_targ_file = os.path.join(proc["outdir"], bug, "slice_func.txt")
        copy_cmd = "cp %s %s" % (inst_targ_file, os.path.join(dst_dir, bug))
        run_cmd(copy_cmd)
        # Now, copy DFG information file.
        dst_dir = os.path.join(INPUT_DIR, "dfg")
        os.makedirs(dst_dir, exist_ok=True)
        dfg_file = os.path.join(proc["outdir"], bug, "slice_dfg.txt")
        copy_cmd = "cp %s %s" % (dfg_file, os.path.join(dst_dir, bug))
        run_cmd(copy_cmd)

def main():
    if len(sys.argv) != 3:
        print("Usage: %s <benchmark> <thin/naive>" % sys.argv[0])
        exit(1)

    benchmark = sys.argv[1]
    thin = True if sys.argv[2] == "thin" else False

    setup_global(benchmark)

    os.makedirs(SPARROW_OUT_DIR, exist_ok=True)
    run_sparrow(benchmark, thin)
    shutil.rmtree(SPARROW_OUT_DIR, ignore_errors=True)

if __name__ == '__main__':
    main()
