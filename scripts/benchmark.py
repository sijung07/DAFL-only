from triage import *

# (target bin, target cmdline, input src, additional option, triage function)
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

#EVAL_FUZZ_TARGETS = [
#    ("swftophp-4.7-2017-9988", "@@", "file", check_swftophp_2017_9988),
#    ("swftophp-4.8-2019-12982", "@@", "file", check_swftophp_2019_12982),
#    ("objcopy-2017-8393", "--compress-debug-sections @@ out", "file", \
#        check_objcopy_2017_8393),
#    ("readelf-2017-16828", "-w @@", "file", check_readelf_2017_16828),
#    ("xmllint-2017-5969", "--recover @@", "file", check_xmllint_2017_5969),
#    ("xmllint-2017-9048", "--valid @@", "file", check_xmllint_2017_9048),
#]

under5000 = [
    "swftophp-4.7-2016-9827",
    "swftophp-4.7-2016-9829",
    "swftophp-4.7-2016-9831",
    "swftophp-4.7-2017-9988",

    "swftophp-4.7-2017-11728",
    "swftophp-4.7-2017-11729",
    "swftophp-4.7.1-2017-7578",
    "swftophp-4.8-2018-11095",

    "lrzip-ed51e14-2018-11496",
    "cxxfilt-2016-4487",
    "cxxfilt-2016-4489",
    "cxxfilt-2016-4490",

    "cxxfilt-2016-4492",
    "objcopy-2017-8393",
    "objcopy-2017-8394",
    "objcopy-2017-8395",
    
    "objdump-2017-8392",
    "strip-2017-7303",
    "readelf-2017-16828",
    "xmllint-2017-5969",
]

under21600 = [
    "swftophp-4.8-2018-20427",
    "swftophp-4.8-2019-12982",
    "objdump-2017-8398",
    "xmllint-2017-9048",
]

under43200 = [
    "swftophp-4.8-2018-11225",
    "swftophp-4.8-2018-11226",
    "swftophp-4.8.1-2019-9114",
    "swftophp-4.8-2020-6628",
]

under86400 = [
    "objdump-2017-8397",
    "nm-2017-14940",
    "xmllint-2017-9047",
    "cjpeg-1.5.90-2018-14498",
]

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


def generate_fuzzing_worklist(benchmark, iteration):
    worklist = []
    TARGETS = FUZZ_TARGETS[benchmark]

    for (prog, bug, cmdline, src, _) in TARGETS:
        if src not in ["stdin", "file"]:
            print("Invalid input source specified: %s" % src)
            exit(1)
        for i in range(iteration):
            worklist.append((benchmark, prog, bug, cmdline, src, i))

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
    benchmark, _, bug, _, _, _ = targ
    for (_, targ_bug, _, _, crash_checker) in FUZZ_TARGETS[benchmark]:
        if targ_bug == bug:
            return crash_checker(replay_buf)
    print("Unknown target: %s" % targ)
    exit(1)
