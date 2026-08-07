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
import sys, os, time, argparse, subprocess

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
IMAGE_NAME = "gdfuzz"
PREPARE_SCRIPT = os.path.join(
    BASE_DIR, "docker-setup", "tool-script", "prepare_custom.sh")


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
    if "PREPARE_DONE" not in (p.stdout or ""):
        print("[!] Preparation failed for %s; skipping this run." % container)
        run("docker kill %s" % container, check=False)
        return None

    # 4. Run the actual fuzzing campaign (detached).
    fuzz = ("/tool-script/run_DAFL.sh %s \"%s\" %s %d"
            % (bin_name, cmdline, args.input, args.time))
    docker_exec(container, fuzz, detached=True)
    return container


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
    containers = []
    for i in range(args.iters):
        c = fuzz_one(args, "iter-%d" % i, cpu=i)
        if c:
            containers.append(c)

    if not containers:
        print("[!] No runs started successfully.")
        sys.exit(1)

    wait_finish(containers, args.time)

    # Collect outputs and clean up.
    for c in containers:
        run("docker cp %s:/output %s/%s" % (c, outdir, c), check=False)
        run("docker kill %s" % c, check=False)

    print("\n[*] Done. Results saved under:\n    %s" % outdir)
    print("    - crashes/      : crashing inputs found by AFL")
    print("    - replay_log.txt: ASAN replay of each crash")


if __name__ == "__main__":
    main()
