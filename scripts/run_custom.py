#!/usr/bin/env python3
#
# run_custom.py — Fuzz an arbitrary single-file C target with DAFL, given only
# the source file and the target line.
#
# Unlike scripts/run.py (which can only fuzz targets that were pre-analyzed and
# baked into the Docker image), this script does the whole DAFL pipeline at
# runtime inside a fresh container spawned from the existing `gdfuzz` image:
#
#   source.c + line  ->  preprocess -> Sparrow slice -> DAFL build -> afl-fuzz
#
# No image rebuild is required: the source file and the preparation script are
# copied into the running container with `docker cp`.
#
# Usage:
#   python3 scripts/run_custom.py <source.c> <line> [time] [iters] [options]
#
# Example (the bundled simple_abort.c, target line 21, 60s, 1 run):
#   python3 scripts/run_custom.py new-targets/simple_abort.c 21 60 1
#
# The target line must be a statement that *uses data* (line 21 is the
# `if (byte == '!')` branch). Pointing at `abort();` on line 24 leaves the DFG
# slice empty and Sparrow fails with `empty list to list_max()`.
#
import sys, os, re, time, json, argparse, subprocess

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
IMAGE_NAME = "gdfuzz"
PREPARE_SCRIPT = os.path.join(
    BASE_DIR, "docker-setup", "tool-script", "prepare_custom.sh")
# In-container file that receives the fuzzing campaign's stdout/stderr.
FUZZ_LOG = "/fuzz_log.txt"
# Lines kept from each end of the fuzzing log (it grows with the time limit).
FUZZ_LOG_KEEP = 50
ANSI_ESCAPE = re.compile(r"\x1b(\[[0-9;?]*[A-Za-z]|\([A-Za-z0-9])")


def run(cmd, check=True, capture=True):
    print("[*] %s" % cmd)
    p = subprocess.run(cmd, shell=True,
                       stdout=subprocess.PIPE if capture else None,
                       stderr=subprocess.STDOUT if capture else None,
                       text=True)
    if capture and p.stdout:
        print(p.stdout, end="")
    if check and p.returncode != 0:
        print("[!] Command failed (exit %d): %s" % (p.returncode, cmd))
        sys.exit(1)
    return p


def docker_exec(container, cmd, detached=False, check=True):
    flag = "-d" if detached else ""
    # Pass the inner command as a single argv element to keep quoting intact.
    full = ["docker", "exec", flag, container, "/bin/bash", "-c", cmd]
    full = [a for a in full if a]
    print("[*] (in %s) %s" % (container, cmd))
    p = subprocess.run(full, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    if p.stdout:
        print(p.stdout, end="")
    if check and p.returncode != 0:
        print("[!] In-container command failed (exit %d)" % p.returncode)
        sys.exit(1)
    return p


def fuzz_one(args, iter_id, cpu):
    bin_name = args.bin_name
    container = "%s-custom-%s" % (bin_name, iter_id)
    src_base = os.path.basename(args.source)
    cmdline = args.cmdline

    # Make sure no stale container with the same name exists.
    run("docker rm -f %s" % container, check=False)

    # 1. Spawn a container from the prebuilt gdfuzz image.
    run("docker run --tmpfs /box:exec --rm -m=%dg --cpuset-cpus=%d -it -d "
        "--name %s %s" % (args.mem, cpu, container, IMAGE_NAME))

    # 2. Copy the source and the preparation script into the container.
    docker_exec(container, "mkdir -p /custom")
    run("docker cp \"%s\" %s:/custom/%s" % (args.source, container, src_base))
    run("docker cp \"%s\" %s:/tool-script/prepare_custom.sh"
        % (PREPARE_SCRIPT, container))

    # 3. Run the preparation pipeline (preprocess -> sparrow -> build).
    prep = ("chmod +x /tool-script/prepare_custom.sh && "
            "/tool-script/prepare_custom.sh %s /custom/%s %d %s '%s'"
            % (bin_name, src_base, args.line, args.entry, args.cflags))
    p = docker_exec(container, prep, check=False)
    prep_log = p.stdout or ""
    if "PREPARE_DONE" not in prep_log:
        print("[!] Preparation failed for %s; skipping this run." % container)
        run("docker kill %s" % container, check=False)
        return container, prep_log, False

    # 4. Run the actual fuzzing campaign (detached). Its output is kept in
    #    FUZZ_LOG so that a campaign which aborts early can still be diagnosed.
    fuzz = ("/tool-script/run_DAFL.sh %s \"%s\" %s %d > %s 2>&1"
            % (bin_name, cmdline, args.input, args.time, FUZZ_LOG))
    docker_exec(container, fuzz, detached=True)
    return container, prep_log, True


def write_text(path, text):
    with open(path, "w") as f:
        f.write(ANSI_ESCAPE.sub("", text))


def save_fuzz_log(container, dst):
    # Keep only the head (startup, abort reason) and the tail (last progress).
    keep = FUZZ_LOG_KEEP
    cmd = ("n=$(wc -l < {log}); if [ $n -le {both} ]; then cat {log}; else "
           "head -n {keep} {log}; echo \"... ($((n - {both})) lines omitted) ...\"; "
           "tail -n {keep} {log}; fi").format(log=FUZZ_LOG, keep=keep,
                                             both=2 * keep)
    p = subprocess.run(["docker", "exec", container, "/bin/bash", "-c", cmd],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       text=True, errors="replace")
    write_text(dst, p.stdout or "")


def write_run_info(outdir, args, statuses):
    info = {
        "source": os.path.basename(args.source),
        "target_line": args.line,
        "bin_name": args.bin_name,
        "cmdline": args.cmdline,
        "input": args.input,
        "entry": args.entry,
        "cflags": args.cflags,
        "time_limit_sec": args.time,
        "iterations": args.iters,
        "runs": [{"name": c, "status": s} for (c, s) in statuses],
    }
    with open(os.path.join(outdir, "run_info.json"), "w") as f:
        json.dump(info, f, indent=2)


def wait_finish(containers, timelimit):
    time.sleep(timelimit)
    elapsed = 0
    while elapsed <= 120:
        done = 0
        for c in containers:
            stat = docker_exec(c, "cat /STATUS 2>/dev/null", check=False)
            if "FINISHED" in (stat.stdout or ""):
                done += 1
            else:
                print("%s not finished" % c)
        if done == len(containers):
            print("[*] All runs finished!")
            return
        time.sleep(60)
        elapsed += 1
        print("[*] Waited %d extra min" % elapsed)


def main():
    ap = argparse.ArgumentParser(
        description="Fuzz a single-file C target with DAFL using only the "
                    "source file and the target line.")
    ap.add_argument("source", help="Path to the C source file")
    ap.add_argument("line", type=int, help="Target line number in the source")
    ap.add_argument("time", nargs="?", type=int, default=60,
                    help="Time limit per run in seconds (default: 60)")
    ap.add_argument("iters", nargs="?", type=int, default=1,
                    help="Number of fuzzing iterations (default: 1)")
    ap.add_argument("--bin-name", default=None,
                    help="Target/binary name (default: source filename stem)")
    ap.add_argument("--cmdline", default="@@",
                    help="Target cmdline; '@@' is replaced by the input file "
                         "(default: '@@')")
    ap.add_argument("--input", choices=["file", "stdin"], default="file",
                    help="Input source kind (default: file)")
    ap.add_argument("--entry", default="main",
                    help="Entry point for Sparrow (default: main)")
    ap.add_argument("--cflags", default="",
                    help="Extra CFLAGS, applied to preprocessing as well as "
                         "both builds, so -I/-D reach the Sparrow frontend "
                         "input (default: none)")
    ap.add_argument("--mem", type=int, default=4,
                    help="Memory per container in GB (default: 4)")
    args = ap.parse_args()

    args.source = os.path.abspath(args.source)
    if not os.path.isfile(args.source):
        print("[!] Source file not found: %s" % args.source)
        sys.exit(1)
    if args.bin_name is None:
        stem = os.path.basename(args.source)
        args.bin_name = stem[:-2] if stem.endswith(".c") else stem
    if args.input == "stdin":
        args.cmdline = ""  # AFL feeds the input on stdin; no @@ needed.

    outdir = os.path.join(
        BASE_DIR, "output",
        "%s-custom-%dsec-%diters" % (args.bin_name, args.time, args.iters))
    os.makedirs(outdir, exist_ok=True)

    # Spawn + prepare + launch every iteration, then wait for all to finish.
    # Every run directory gets prepare_log.txt; run_info.json records the
    # settings (incl. the target line) and how each run ended.
    containers = []
    statuses = []
    for i in range(args.iters):
        c, prep_log, ok = fuzz_one(args, "iter-%d" % i, cpu=i)
        statuses.append([c, "running"])
        if ok:
            containers.append((c, prep_log))
        else:
            os.makedirs(os.path.join(outdir, c), exist_ok=True)
            write_text(os.path.join(outdir, c, "prepare_log.txt"), prep_log)
            statuses[-1][1] = "prepare_failed"

    if not containers:
        write_run_info(outdir, args, statuses)
        print("[!] No runs started successfully. See prepare_log.txt under:"
              "\n    %s" % outdir)
        sys.exit(1)

    wait_finish([c for (c, _) in containers], args.time)

    # Collect outputs and clean up.
    for c, prep_log in containers:
        rundir = os.path.join(outdir, c)
        p = run("docker cp %s:/output %s" % (c, rundir), check=False)
        os.makedirs(rundir, exist_ok=True)
        write_text(os.path.join(rundir, "prepare_log.txt"), prep_log)
        save_fuzz_log(c, os.path.join(rundir, "fuzz_log.txt"))
        for st in statuses:
            if st[0] == c:
                st[1] = "finished" if p.returncode == 0 else "no_output"
        run("docker kill %s" % c, check=False)

    write_run_info(outdir, args, statuses)

    print("\n[*] Done. Results saved under:\n    %s" % outdir)
    print("    - run_info.json  : settings (incl. target line) and run status")
    print("    - crashes/       : crashing inputs found by AFL")
    print("    - replay_log.txt : ASAN replay of each crash")
    print("    - prepare_log.txt: preprocessing / Sparrow / build log")
    print("    - fuzz_log.txt   : fuzzing log (head and tail)")


if __name__ == "__main__":
    main()
