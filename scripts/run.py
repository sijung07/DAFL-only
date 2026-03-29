import sys, os, time
from common import run_cmd, run_cmd_arr, check_cpu_count
from benchmark import generate_fuzzing_worklist
from parse_result import print_result

BASE_DIR = "/results"

def decide_basedir(experiment, timelimit, iteration):
    name = "%s-%ssec-%siters" % (experiment, timelimit, iteration)
    outdir = os.path.join(BASE_DIR, name)
    return outdir

def decide_outdir(experiment, bug, timelimit, iteration, iter_id):
    name = "%s-%ssec-%siters" % (experiment, timelimit, iteration)
    outdir = os.path.join(BASE_DIR, name, "%s-iter-%d" % (bug, iter_id))
    os.makedirs(outdir, exist_ok=True)
    return outdir

def run_fuzzing(work, timelimit, outdir):
    benchmark, prog, bug, cmdline, src, iter_id = work
    cmd = ['/tool-script/run_DAFL.sh', benchmark, prog, bug, cmdline, src, str(timelimit), str(iter_id), outdir]
    run_cmd_arr(cmd)

def wait_finish(work, timelimit):
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
    for work in worklist:
        _, _, bug, _, _, iter_id = work
        outdir = decide_outdir(experiment, bug, str(timelimit), str(iteration), iter_id)
        run_fuzzing(work, timelimit, outdir)
        wait_finish(work, timelimit)

    ### 2. Parse and print results in CSV and TSV format
    outdir = decide_basedir(experiment, str(timelimit), str(iteration))
    print_result(outdir, worklist, timelimit, iteration)

    #### 3. Draw bar plot with TSV file
    #draw_result(outdir, target)

if __name__ == "__main__":
    main()
