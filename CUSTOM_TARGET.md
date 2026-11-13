# Source-File Fuzzing (Custom Target Fuzzing)

This feature runs directed fuzzing on a single-file C program **given just two
inputs: the source file and the target line**. Preprocessing, static analysis,
build, fuzzing, and crash replay all run automatically with a single command.

```bash
./fuzz_custom.sh new-targets/simple_abort.c 21 60 1
```

The command above fuzzes `new-targets/simple_abort.c` for 60 seconds, once,
targeting **line 21** (`if (byte == '!')`). (The same command is also in
`new_target.sh`.)

> **Tip on choosing the target line:** DAFL guides fuzzing along the *data
> dependency (DFG)* toward the target, so choose a statement that uses a
> variable or value. For example, instead of a bare `abort();`, target the
> branch condition right before it (`if (byte == '!')`, line 21).

---

## 1. Prerequisites

1. **The `gdfuzz` Docker image**
   - Build the image: `./build.sh`
   - Or load the provided tar: `docker load -i gdfuzz.docker.tar`
   - Check: `docker images | grep gdfuzz`
2. **A Linux host with Docker** (see the system settings in README 1.1/1.2).
   - AFL core dump pattern: `echo core | sudo tee /proc/sys/kernel/core_pattern`
3. **The source file to fuzz and the target line number**

---

## 2. Usage

```bash
./fuzz_custom.sh <source.c> <target_line> [timelimit] [iterations]
```

For more options, call the Python script directly.

```bash
python3 scripts/run_custom.py <source.c> <line> [time] [iters] [options]
```

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `time` | `60` | Time limit per run (seconds) |
| `iters` | `1` | Number of runs (each in its own container/core) |
| `--bin-name` | Source file name without extension | Target/binary name |
| `--cmdline` | `@@` | Target arguments. `@@` is replaced by the input file path |
| `--input` | `file` | How input is passed: `file` (`@@`) or `stdin` |
| `--entry` | `main` | Entry point for static analysis |
| `--cflags` | (none) | Extra compiler options (`-I`, `-D`, `-l...`, etc.). Applied to both preprocessing and build |
| `--mem` | `4` | Memory per container (GB) |

### Examples

```bash
# Target that reads its input from a file argument
python3 scripts/run_custom.py new-targets/simple_abort.c 21 60 1

# Target that reads its input from stdin
python3 scripts/run_custom.py new-targets/simple_abort.c 21 60 1 --input stdin

# Target that takes extra arguments/flags
python3 scripts/run_custom.py mytool.c 130 300 4 --cmdline "-d @@"
```

---

## 3. Results

Results are stored under the following path.

```
output/<bin_name>-custom-<time>sec-<iters>iters/
├─ run_info.json        <- run settings (source file, target line, ...) and per-run status
└─ <bin_name>-custom-iter-<n>/
   ├─ crashes/          <- inputs that caused a crash
   ├─ hangs/
   ├─ replay_log.txt    <- ASAN replay log of each crash
   ├─ prepare_log.txt   <- preprocessing / static analysis / build log
   ├─ fuzz_log.txt      <- fuzzing log (first and last 50 lines)
   └─ ...
```

`runs[].status` in `run_info.json` is one of the following for each run.

| status | Meaning | Details in |
|---|---|---|
| `finished` | Fuzzing completed and results were collected | - |
| `prepare_failed` | Stopped during preprocessing, analysis, or build | `prepare_log.txt` |
| `fuzz_failed` | Fuzzing stopped right after start (e.g., every initial input crashes, system settings) | `fuzz_log.txt` |

For `simple_abort.c`, if the first byte of a crashing input is `!`,
`replay_log.txt` records `SIMPLE_ABORT_TRIGGERED` and the abort signal.

---

## 4. How It Works

`run_custom.py` (host) and `prepare_custom.sh` (inside the container) perform
the following steps in order.

1. Create a container from the `gdfuzz` image.
2. Copy the source file into the container.
3. **Preprocess**: generate the static analysis input (`.i`) with `clang -E`.
4. **Static analysis**: Sparrow slices with respect to the target line and produces
   - `slice_func.txt` (functions to instrument → `DAFL_SELECTIVE_COV`)
   - `slice_dfg.txt` (data-flow-graph scores → `DAFL_DFG_SCORE`).
5. **DAFL build**: `afl-clang-fast` + the two environment variables above + `-fsanitize=address`.
6. **ASAN build**: binary for crash replay.
7. **Fuzzing and replay**: fuzz with `run_DAFL.sh`, then replay the crashes found with ASAN.

Related files:

- `scripts/run_custom.py` — runs the whole process
- `docker-setup/tool-script/prepare_custom.sh` — preparation steps inside the container
- `fuzz_custom.sh` — convenience wrapper

---

## 5. Notes

- This feature is designed for **single-file C programs**. For projects made of
  multiple source files, follow the target-adding procedure in README 5.1.
- The target line must be **a line that can execute from the entry point
  (`--entry`, default `main`)**. Otherwise the run stops at the analysis step
  with a message, which can be found in `prepare_log.txt`.
- Fuzzing starts from the empty seed included in the image
  (`/benchmark/seed/empty`).
- Increasing `iters` assigns one container to each of cores 0..N-1. Do not use
  a value larger than the number of cores.
