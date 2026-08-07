# 커스텀 타겟 퍼징 (Custom Target Fuzzing)

기존 DAFL-only는 Docker 이미지에 미리 분석·빌드되어 들어간 벤치마크 타겟만
퍼징할 수 있었습니다. 이 기능은 **소스 파일과 타겟 라인 두 가지만 입력하면**
임의의 단일 파일 C 프로그램을 DAFL로 퍼징할 수 있게 해 줍니다.

```bash
./fuzz_custom.sh new-targets/simple_abort.c 21 60 1
```

위 명령은 `new-targets/simple_abort.c`의 **21번째 줄**(`if (byte == '!')`)을
타겟으로 60초, 1회 퍼징을 수행합니다. (동일한 명령이 `new_target.sh`에도 있습니다.)

> ⚠️ **타겟 라인은 "데이터를 사용하는" 실행문이어야 합니다.** DAFL은 타겟까지의
> *데이터 의존성(DFG)* 으로 퍼징을 유도합니다. 따라서 `abort();`/`exit();` 처럼
> 인자가 없는 제어문을 타겟으로 잡으면 DFG 슬라이스가 비어 Sparrow가 실패합니다
> (`empty list to list_max()`). `abort()`로 이어지는 **분기 조건**
> (`if (byte == '!')`, 라인 21)처럼 변수를 쓰는 줄을 타겟으로 지정하세요.

---

## 1. 사전 준비 (사용자가 해야 할 일)

추가 기능 자체는 자동이지만, **다음 환경 조건**은 기존 아티팩트와 동일하게
사용자가 갖춰야 합니다.

1. **`gdfuzz` Docker 이미지가 로드되어 있어야 합니다.**
   - 이미지 빌드: `./build.sh`
   - 또는 제공된 tar 로드: `docker load -i gdfuzz.docker.tar`
   - 확인: `docker images | grep gdfuzz`
2. **Linux 호스트 + Docker** 환경 (README의 1.1/1.2 시스템 설정 참고).
   - AFL 코어 덤프 패턴: `echo core | sudo tee /proc/sys/kernel/core_pattern`
3. **퍼징할 소스 파일과 타겟 라인 번호.** (이게 핵심 입력입니다.)

> 즉, 사용자가 매번 직접 해야 하는 작업은 **`.c` 파일과 라인 번호를 넘기는 것**
> 뿐이며, 전처리 → 정적 분석 → 빌드 → 퍼징은 모두 자동으로 수행됩니다.

---

## 2. 사용법

```bash
./fuzz_custom.sh <source.c> <target_line> [timelimit] [iterations]
```

또는 더 많은 옵션이 필요하면 파이썬 스크립트를 직접 호출합니다.

```bash
python3 scripts/run_custom.py <source.c> <line> [time] [iters] [options]
```

### 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `time` | `60` | 실행당 시간 제한(초) |
| `iters` | `1` | 반복 실행 횟수 (각각 별도 컨테이너/코어) |
| `--bin-name` | 소스 파일명(확장자 제거) | 타겟/바이너리 이름 |
| `--cmdline` | `@@` | 타겟 실행 인자. `@@`는 입력 파일 경로로 치환됨 |
| `--input` | `file` | 입력 전달 방식: `file`(`@@`) 또는 `stdin` |
| `--entry` | `main` | Sparrow 분석 진입점 |
| `--cflags` | (없음) | 추가 CFLAGS. **전처리 단계에도 적용**되므로 `-I`, `-D`가 필요한 소스도 처리된다. `-l...` 는 소스 파일 뒤에 놓여 정상 링크된다 |
| `--mem` | `4` | 컨테이너당 메모리(GB) |

### 예시

```bash
# 파일 인자로 입력을 받는 타겟
python3 scripts/run_custom.py new-targets/simple_abort.c 21 60 1

# stdin으로 입력을 받는 타겟
python3 scripts/run_custom.py new-targets/simple_abort.c 21 60 1 --input stdin

# 타겟이 별도 인자/플래그를 받는 경우
python3 scripts/run_custom.py mytool.c 130 300 4 --cmdline "-d @@"
```

---

## 3. 결과 확인

결과는 다음 경로에 저장됩니다.

```
output/<bin_name>-custom-<time>sec-<iters>iters/<bin_name>-custom-iter-<n>/
├─ crashes/         <- AFL이 찾은 크래시 입력
├─ hangs/
├─ replay_log.txt   <- 각 크래시를 ASAN 바이너리로 재현한 로그
└─ ...
```

`simple_abort.c`의 경우, 크래시 입력의 첫 바이트가 `!`이면
`replay_log.txt`에 `SIMPLE_ABORT_TRIGGERED`와 abort 신호가 기록됩니다.

---

## 4. 내부 동작 (자동화되는 파이프라인)

`run_custom.py`(호스트) → `prepare_custom.sh`(컨테이너 내부) 순으로 실행되며,
다음을 **이미지 재빌드 없이** 런타임에 수행합니다.

1. `gdfuzz` 이미지로 컨테이너 생성.
2. 소스 파일과 `prepare_custom.sh`를 `docker cp`로 컨테이너에 복사.
3. **전처리**: `clang -E` 로 `.i` 생성 (Sparrow CIL 프론트엔드 입력).
4. **정적 분석**: Sparrow가 `target=<file>:<line>` 기준으로 슬라이싱하여
   - `slice_func.txt` (계측 대상 함수 목록 → `DAFL_SELECTIVE_COV`)
   - `slice_dfg.txt` (데이터 흐름 그래프 점수 → `DAFL_DFG_SCORE`) 생성.
5. **DAFL 빌드**: `afl-clang-fast` + 위 두 환경변수 + `-fsanitize=address`.
6. **ASAN 빌드**: 크래시 재현/검증용 바이너리.
7. **퍼징**: 기존 `run_DAFL.sh`로 `afl-fuzz` 실행, 끝나면 크래시를 ASAN으로 재현.

추가/수정된 파일:

- `scripts/run_custom.py` — 호스트 오케스트레이터
- `docker-setup/tool-script/prepare_custom.sh` — 컨테이너 내부 준비 파이프라인
- `fuzz_custom.sh` — 편의 래퍼

---

## 5. 제약 및 참고 사항

- **단일 파일 C 타겟**을 대상으로 합니다. 여러 소스 파일/복잡한 빌드 시스템을
  가진 프로젝트는 전처리 단계에서 `smake`가 필요하며, 이는
  `docker-setup/run-smake.sh`와 `benchmark.py`의 `SLICE_TARGETS`에 타겟을
  추가하는 기존 절차(README 5.1)를 따라야 합니다.
- 타겟 라인은 **진입점(`--entry`, 기본 `main`)에서 도달 가능한 실행문**이어야
  합니다. 도달 불가능하면 Sparrow가 슬라이스를 생성하지 못하고 스크립트가
  오류와 함께 중단됩니다.
- 타겟 라인은 **데이터를 사용하는 실행문**이어야 합니다(위 ⚠️ 참고). 인자가
  없는 `abort()`/`exit()` 같은 줄은 DFG가 비어 Sparrow가
  `empty list to list_max()`로 실패합니다. 이럴 땐 그 직전의 데이터 분기
  (변수를 비교/사용하는 줄)를 타겟으로 지정하세요.
- 시드를 따로 지정하지 않으면 이미지에 포함된 빈 시드(`/benchmark/seed/empty`)가
  사용됩니다. 더 좋은 초기 시드가 있으면 컨테이너의 `/benchmark/seed/<bin_name>/`에
  넣어 확장할 수 있습니다.
- `iters`를 늘리면 코어 0..N-1에 각각 컨테이너가 배정됩니다. 코어 수보다 큰
  값을 주지 않도록 주의하세요.
