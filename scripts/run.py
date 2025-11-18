import sys, os, time
from common import run_cmd, run_cmd_arr, check_cpu_count
from benchmark import generate_fuzzing_worklist

BASE_DIR = "/results"

def decide_outdir(benchmark, bug, timelimit, iteration, tool):
    name = "%s-%s-%ssec-%siters" % (benchmark, bug, timelimit, iteration)
    outdir = os.path.join(BASE_DIR, "output", name, tool)
    os.makedirs(outdir, exist_ok=True)
    return outdir

def run_fuzzing(work, tool, timelimit, outdir):
    benchmark, prog, bug, cmdline, src, iter_id = work
    cmd = ['/tool-script/run_%s.sh' % tool, benchmark, prog, bug, cmdline, src, str(timelimit), str(iter_id), outdir]
    res = run_cmd_arr(cmd)
    print(res)

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
    if len(sys.argv) < 3:
        print("Usage: %s <target name> <time> <iterations>" % sys.argv[0])
        exit(1)

    check_cpu_count()

    benchmark = sys.argv[1]
    timelimit = int(sys.argv[2])
    iteration = int(sys.argv[3])

    #if "origin" in target:
    #    target = target.split("-")[1]

    #if target == "test":
    #    target = "lrzip-ed51e14-2018-11496"
    #    benchmark = target
    #    target_list = [target]
    #elif "eval" in target:
    #    benchmark = "eval"
    #    target_list = [x for (x,y,z,w) in EVAL_FUZZ_TARGETS]
    #elif target in [x for (x,y,z,w) in FUZZ_TARGETS]:
    #    benchmark = target
    #    target_list = [target]
    #else:
    #    print("Invalid target!")

    ### 1. Run fuzzing
    tool = "DAFL"
    worklist = generate_fuzzing_worklist(benchmark, iteration)
    for work in worklist:
        benchmark, _, bug, _, _, _ = work
        outdir = decide_outdir(benchmark, bug, str(timelimit), str(iteration), tool)
        run_fuzzing(work, tool, timelimit, outdir)
        wait_finish(work, timelimit)
        break

        #### Reset timelimit to user input
        #timelimit = int(sys.argv[2])

    #if "origin" in sys.argv[1]:
    #    outdir = decide_outdir("origin", "", "", "")
    #else:
    #    outdir = decide_outdir(target, str(timelimit), str(iteration), "")

    #### 2. Parse and print results in CSV and TSV format
    #print_result(outdir, target, target_list, timelimit,  iteration, [tool])

    #### 3. Draw bar plot with TSV file
    #draw_result(outdir, target)


if __name__ == "__main__":
    main()
