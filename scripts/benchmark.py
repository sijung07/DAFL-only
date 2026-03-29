from triage import *

LEGACY_BENCHMARK_NAMES = {
    'libming-4.7-swftophp': 'swftophp-4.7',
    'libming-4.7.1-swftophp': 'swftophp-4.7.1',
    'libming-4.8-swftophp': 'swftophp-4.8',
    'libming-4.8.1-swftophp': 'swftophp-4.8.1',
    'lrzip-9de7ccb-lrzip': 'lrzip-9de7ccb',
    'lrzip-ed51e14-lrzip': 'lrzip-ed51e14',
    'binutils-2.26-cxxfilt': 'cxxfilt',
    'binutils-2.27-strip': 'strip',
    'binutils-2.28-objcopy': 'objcopy',
    'binutils-2.28-objdump': 'objdump',
    'binutils-2.29-nm': 'nm',
    'binutils-2.29-readelf': 'readelf',
    'binutils-2.31.1-objdump': 'objdump-2.31.1',
    'libxml2-2.9.4-xmllint': 'xmllint',
    'libjpeg-1.5.90-cjpeg': 'cjpeg-1.5.90',
    'libjpeg-2.0.4-cjpeg': 'cjpeg-2.0.4',
}

# Dictionary<target, List<(program, bug_id, cmdline, input_source, crash_checker)>>
FUZZ_TARGETS = {
    'libming-4.7-swftophp': [
        ("swftophp", "2016-9827", "@@", "file", check_swftophp_2016_9827),
        ("swftophp", "2016-9827", "@@", "file", check_swftophp_2016_9827),
        ("swftophp", "2016-9829", "@@", "file", check_swftophp_2016_9829),
        ("swftophp", "2016-9831", "@@", "file", check_swftophp_2016_9831),
        ("swftophp", "2017-9988", "@@", "file", check_swftophp_2017_9988),
        ("swftophp", "2017-11728", "@@", "file", check_swftophp_2017_11728),
        ("swftophp", "2017-11729", "@@", "file", check_swftophp_2017_11729)],
    'libming-4.7.1-swftophp': [("swftophp", "2017-7578", "@@", "file", check_swftophp_2017_7578)],
    'libming-4.8-swftophp': [
        ("swftophp", "2018-7868", "@@", "file", check_swftophp_2018_7868),
        ("swftophp", "2018-8807", "@@", "file", check_swftophp_2018_8807),
        ("swftophp", "2018-8962", "@@", "file", check_swftophp_2018_8962),
        ("swftophp", "2018-11095", "@@", "file", check_swftophp_2018_11095),
        ("swftophp", "2018-11225", "@@", "file", check_swftophp_2018_11225),
        ("swftophp", "2018-11226", "@@", "file", check_swftophp_2018_11226),
        ("swftophp", "2018-20427", "@@", "file", check_swftophp_2018_20427),
        ("swftophp", "2019-12982", "@@", "file", check_swftophp_2019_12982),
        ("swftophp", "2020-6628", "@@", "file", check_swftophp_2020_6628)],
    'libming-4.8.1-swftophp': [("swftophp", "2019-9114", "@@", "file", check_swftophp_2019_9114)],
    'lrzip-9de7ccb-lrzip': [("lrzip", "2017-8846", "-m 10 -t @@", "file", check_lrzip_2017_8846)],
    'lrzip-ed51e14-lrzip': [("lrzip", "2018-11496", "-t @@", "file", check_lrzip_2018_11496)],
    'binutils-2.26-cxxfilt': [
        ("cxxfilt", "2016-4487", "", "stdin", check_cxxfilt_2016_4487),
        ("cxxfilt", "2016-4489", "", "stdin", check_cxxfilt_2016_4489),
        ("cxxfilt", "2016-4490", "", "stdin", check_cxxfilt_2016_4490),
        ("cxxfilt", "2016-4491", "", "stdin", check_cxxfilt_2016_4491),
        ("cxxfilt", "2016-4492", "", "stdin", check_cxxfilt_2016_4492),
        ("cxxfilt", "2016-6131", "", "stdin", check_cxxfilt_2016_6131)],
    'binutils-2.28-objcopy': [
        ("objcopy", "2017-8393", "--compress-debug-sections @@ out", "file", \
            check_objcopy_2017_8393),
        ("objcopy", "2017-8394", "-Gs @@ out", "file",  \
            check_objcopy_2017_8394),
        ("objcopy", "2017-8395", "--compress-debug-sections @@ out", "file", \
            check_objcopy_2017_8395)],
    'binutils-2.28-objdump': [
        ("objdump", "2017-8392", "-SD @@", "file", check_objdump_2017_8392),
        ("objdump", "2017-8396", "-W @@", "file", check_objdump_2017_8396),
        ("objdump", "2017-8397", "-W @@", "file", check_objdump_2017_8397),
        ("objdump", "2017-8398", "-W @@", "file", check_objdump_2017_8398)],
    'binutils-2.31.1-objdump': [
        ("objdump", "2018-17360", "--dwarf-check -C -g -f -dwarf -x @@", "file", \
            check_objdump_2018_17360)],
    'binutils-2.27-strip': [("strip", "2017-7303", "-o /dev/null @@", "file", check_strip_2017_7303)],
    'binutils-2.29-nm': [
        ("nm", "2017-14940", "-A -a -l -S -s --special-syms --synthetic --with-symbol-versions -D @@", \
            "file", check_nm_2017_14940)],
    'binutils-2.29-readelf': [("readelf", "2017-16828", "-w @@", "file", check_readelf_2017_16828)],
    'libxml2-2.9.4-xmllint': [
        ("xmllint", "2017-5969", "--recover @@", "file", check_xmllint_2017_5969),
        ("xmllint", "2017-9047", "--valid @@", "file", check_xmllint_2017_9047),
        ("xmllint", "2017-9048", "--valid @@", "file", check_xmllint_2017_9048)],
    'libjpeg-1.5.90-cjpeg': [
        ("cjpeg", "2018-14498", "-outfile /dev/null @@", "file", \
            check_cjpeg_2018_14498)],
    'libjpeg-2.0.4-cjpeg': [
        ("cjpeg", "2020-13790", "-outfile /dev/null @@", "file", \
            check_cjpeg_2020_13790)],
}

# Dictionary<target, Record>
SLICE_TARGETS = {
    'libming-4.7-swftophp': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2016-9827', '2016-9829', '2016-9831', '2017-9988', '2017-11728', '2017-11729']
    },
    'libming-4.7.1-swftophp': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-7578']
    },
    'libming-4.8-swftophp': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2018-7868', '2018-8807', '2018-8962', '2018-11095', '2018-11225','2018-11226', '2018-20427', '2019-12982', '2020-6628']
    },
    'libming-4.8.1-swftophp': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2019-9114']
    },
    'lrzip-ed51e14-lrzip': {
        'frontend':'clang',
        'entry_point':'main',
        'bugs': ['2018-11496']
    },
    'lrzip-9de7ccb-lrzip': {
        'frontend':'clang',
        'entry_point':'main',
        'bugs': ['2017-8846']
    },
    'binutils-2.28-objdump': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-8392', '2017-8396', '2017-8397', '2017-8398']
    },
    'binutils-2.28-objcopy': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-8393', '2017-8394', '2017-8395']
    },
    'binutils-2.31.1-objdump': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2018-17360']
    },
    'binutils-2.29-nm': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-14940']
    },
    'binutils-2.29-readelf': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-16828']
    },
    'binutils-2.27-strip': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-7303']
    },
    'binutils-2.26-cxxfilt': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': [
            '2016-4487', '2016-4489', '2016-4490', '2016-4491', '2016-4492',
            '2016-6131'
        ]
    },
    'libxml2-2.9.4-xmllint': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2017-5969', '2017-9047', '2017-9048',]
    },
    'libjpeg-1.5.90-cjpeg': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2018-14498']
    },
    'libjpeg-2.0.4-cjpeg': {
        'frontend':'cil',
        'entry_point':'main',
        'bugs': ['2020-13790']
    },
}

EVAL_FUZZ_TARGETS = [
    ('libming-4.7-swftophp', '2016-9829'),
    ('libming-4.7-swftophp', '2017-11729'),
    ('binutils-2.26-cxxfilt', '2016-4487'),
    ('binutils-2.28-objcopy', '2017-8393'),
    ('binutils-2.29-readelf', '2017-16828'),
    ('libxml2-2.9.4-xmllint', '2017-5969'),
]


def iter_fuzz_target_records():
    for benchmark, targets in FUZZ_TARGETS.items():
        for prog, bug, cmdline, src, crash_checker in targets:
            yield benchmark, prog, bug, cmdline, src, crash_checker


def _select_targets_for_bug(benchmark, bug):
    targets = []
    for prog, targ_bug, cmdline, src, crash_checker in FUZZ_TARGETS[benchmark]:
        if targ_bug == bug:
            targets.append((benchmark, prog, targ_bug, cmdline, src, crash_checker))
    return targets


def _build_target_aliases():
    aliases = {}
    for benchmark, _, bug, _, _, _ in iter_fuzz_target_records():
        aliases[f"{benchmark}-{bug}"] = (benchmark, bug)
        aliases[f"{LEGACY_BENCHMARK_NAMES[benchmark]}-{bug}"] = (benchmark, bug)
    return aliases


TARGET_ALIASES = _build_target_aliases()


def resolve_fuzz_targets(target_spec):
    if target_spec == "all":
        return list(iter_fuzz_target_records())

    if target_spec == "eval":
        targets = []
        for benchmark, bug in EVAL_FUZZ_TARGETS:
            targets.extend(_select_targets_for_bug(benchmark, bug))
        return targets

    if target_spec in FUZZ_TARGETS:
        return [
            (target_spec, prog, bug, cmdline, src, crash_checker)
            for prog, bug, cmdline, src, crash_checker in FUZZ_TARGETS[target_spec]
        ]

    if target_spec in TARGET_ALIASES:
        benchmark, bug = TARGET_ALIASES[target_spec]
        return _select_targets_for_bug(benchmark, bug)

    return []


def resolve_crash_checkers(target_spec):
    if isinstance(target_spec, tuple):
        benchmark, _, bug, _, _, _ = target_spec
        return [
            crash_checker
            for _, targ_bug, _, _, crash_checker in FUZZ_TARGETS[benchmark]
            if targ_bug == bug
        ]

    resolved_targets = resolve_fuzz_targets(target_spec)
    if resolved_targets:
        return [crash_checker for _, _, _, _, _, crash_checker in resolved_targets]

    return [
        crash_checker
        for _, _, bug, _, _, crash_checker in iter_fuzz_target_records()
        if bug == target_spec
    ]


def generate_fuzzing_worklist(benchmark, iteration):
    worklist = []
    targets = resolve_fuzz_targets(benchmark)
    if not targets:
        print("Unsupported benchmark: %s" % benchmark)
        exit(1)

    for (resolved_benchmark, prog, bug, cmdline, src, _) in targets:
        if src not in ["stdin", "file"]:
            print("Invalid input source specified: %s" % src)
            exit(1)
        for i in range(iteration):
            worklist.append((resolved_benchmark, prog, bug, cmdline, src, i))

    return worklist


def generate_slicing_worklist(benchmark):
    if benchmark == "all":
        worklist = list(SLICE_TARGETS.keys())
    elif benchmark in SLICE_TARGETS:
        worklist = [benchmark]
    else:
        print("Unsupported benchmark: %s" % benchmark)
        exit(1)
    return worklist


def check_targeted_crash(targ, replay_buf):
    checkers = resolve_crash_checkers(targ)
    if not checkers:
        print("Unknown target: %s" % targ)
        exit(1)
    for crash_checker in checkers:
        if crash_checker(replay_buf):
            return True
    return False
