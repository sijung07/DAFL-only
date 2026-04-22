import os
import shlex
import sys
import time
from common import (
    MEM_PER_INSTANCE,
    check_cpu_count,
    fetch_works,
    run_cmd,
    run_cmd_arr,
)
from benchmark import generate_fuzzing_worklist
from parse_result import print_result

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
REPO_DIR = os.path.realpath(os.path.join(SCRIPT_DIR, os.pardir))
IMAGE_NAME = "gdfuzz"
HOST_PROJECTS_DIR = os.path.join(REPO_DIR, "benchmark")
HOST_RESULTS_DIR = os.path.join(REPO_DIR, "output")
CONTAINER_PROJECTS_DIR = "/projects"
CONTAINER_RESULTS_DIR = "/results"
RUNNING_IN_CONTAINER = os.path.isdir(CONTAINER_PROJECTS_DIR) and os.path.exists("/tool-script/run_DAFL.sh")


def get_results_base_dir():
    if RUNNING_IN_CONTAINER:
        return CONTAINER_RESULTS_DIR
    return HOST_RESULTS_DIR

def decide_basedir(experiment, timelimit, iteration):
    name = "%s-%ssec-%siters" % (experiment, timelimit, iteration)
    outdir = os.path.join(get_results_base_dir(), name)
    return outdir


def decide_outdir(experiment, bug, timelimit, iteration, iter_id):
    name = "%s-%ssec-%siters" % (experiment, timelimit, iteration)
    outdir = os.path.join(get_results_base_dir(), name, "%s-iter-%d" % (bug, iter_id))
    os.makedirs(outdir, exist_ok=True)
    return outdir


def run_fuzzing_in_container(work, timelimit, outdir):
    benchmark, prog, bug, cmdline, src, iter_id = work
    cmd = ['/tool-script/run_DAFL.sh', benchmark, prog, bug, cmdline, src, str(timelimit), str(iter_id), outdir]
    run_cmd_arr(cmd)


def wait_finish_in_container(work, timelimit):
    time.sleep(timelimit)
    elapsed_min = 0
    while True:
        if elapsed_min > 120:
            break
        time.sleep(60)
        elapsed_min += 1
        print("Waited for %d min" % elapsed_min)
        benchmark, _, _, _, _, iter_id = work
        stat_str = str(run_cmd("cat /STATUS"))
        if "FINISHED" in stat_str:
            break
        else:
            print("%s-%s not finished" % (benchmark, iter_id))


def _container_name(work):
    benchmark, prog, bug, _, _, iter_id = work
    name = "%s-%s-%s-iter-%d" % (benchmark, prog, bug, iter_id)
    return name.replace("/", "-")


def _build_host_fuzz_command(work, timelimit):
    benchmark, prog, bug, cmdline, src, iter_id = work
    benchmark_dir = shlex.quote(os.path.join(CONTAINER_PROJECTS_DIR, benchmark))
    command = [
        "set -e",
        "cd %s" % benchmark_dir,
        "if [ ! -d SRC ]; then ./download.sh; fi",
        "if [ ! -d smake ]; then ./run_smake.sh; fi",
        "if [ ! -d DAFL-input ]; then python3 /scripts/run_sparrow.py %s thin; fi" % shlex.quote(benchmark),
        "if [ ! -d DAFL-input-naive ]; then python3 /scripts/run_sparrow.py %s naive; fi" % shlex.quote(benchmark),
        "if [ ! -d bin ]; then ./build_DAFL.sh; fi",
        "if [ ! -d asan ]; then ./build_ASAN.sh; fi",
        "/scripts/prepare.sh %s" % shlex.quote(benchmark),
        "/tool-script/run_DAFL.sh %s %s %s %s %s %d %d %s"
        % (
            shlex.quote(benchmark),
            shlex.quote(prog),
            shlex.quote(bug),
            shlex.quote(cmdline),
            shlex.quote(src),
            timelimit,
            iter_id,
            shlex.quote(CONTAINER_RESULTS_DIR),
        ),
    ]
    return "; ".join(command)


def run_fuzzing_on_host(works, experiment, timelimit, iteration):
    for cpu_id, work in enumerate(works):
        _, _, bug, _, _, _ = work
        outdir = decide_outdir(experiment, bug, str(timelimit), str(iteration), work[-1])
        command = [
            'docker', 'run', '-d', '--name', _container_name(work),
            '-m=%dg' % MEM_PER_INSTANCE,
            '--cpuset-cpus=%d' % cpu_id,
            '-v', '%s:/scripts' % SCRIPT_DIR,
            '-v', '%s:%s' % (HOST_PROJECTS_DIR, CONTAINER_PROJECTS_DIR),
            '-v', '%s:%s' % (outdir, CONTAINER_RESULTS_DIR),
            IMAGE_NAME,
            '/bin/bash', '-lc', _build_host_fuzz_command(work, timelimit),
        ]
        run_cmd_arr(command)


def wait_finish_on_host(works, timelimit):
    time.sleep(timelimit)
    elapsed_min = 0
    while True:
        if elapsed_min > 120:
            break
        time.sleep(60)
        elapsed_min += 1
        print("Waited for %d min" % elapsed_min)
        finished_count = 0
        for work in works:
            container = _container_name(work)
            status = run_cmd_arr(['docker', 'inspect', '-f', '{{.State.Status}}', container]).decode().strip()
            if status == 'exited':
                finished_count += 1
            else:
                print("%s not finished (status: %s)" % (container, status))
        if finished_count == len(works):
            break


def cleanup_host_containers(works):
    for work in works:
        run_cmd_arr(['docker', 'rm', '-f', _container_name(work)])


def unique_targets(worklist):
    seen = set()
    targets = []
    for benchmark, prog, bug, cmdline, src, _ in worklist:
        key = (benchmark, prog, bug, cmdline, src)
        if key in seen:
            continue
        seen.add(key)
        targets.append((benchmark, prog, bug, cmdline, src, 0))
    return targets

def main():
    if len(sys.argv) != 4:
        print("Usage: %s <target name> <time> <iterations>" % sys.argv[0])
        exit(1)

    check_cpu_count()

    experiment = sys.argv[1]
    timelimit = int(sys.argv[2])
    iteration = int(sys.argv[3])

    ### 1. Run fuzzing
    worklist = generate_fuzzing_worklist(experiment, iteration)
    target_list = unique_targets(worklist)

    if RUNNING_IN_CONTAINER:
        for work in worklist:
            _, _, bug, _, _, iter_id = work
            outdir = decide_outdir(experiment, bug, str(timelimit), str(iteration), iter_id)
            run_fuzzing_in_container(work, timelimit, outdir)
            wait_finish_in_container(work, timelimit)
    else:
        pending_worklist = list(worklist)
        while pending_worklist:
            works = fetch_works(pending_worklist)
            run_fuzzing_on_host(works, experiment, timelimit, iteration)
            wait_finish_on_host(works, timelimit)
            cleanup_host_containers(works)

    ### 2. Parse and print results in CSV and TSV format
    outdir = decide_basedir(experiment, str(timelimit), str(iteration))
    print_result(outdir, target_list, timelimit, iteration)

    #### 3. Draw bar plot with TSV file
    #draw_result(outdir, target)

if __name__ == "__main__":
    main()
