# Task 6 testing and verification

Verified date: **2026-10-18** (Asia/Karachi).

Reference: [Task 6 requirements](https://github.com/SeekingDream/ProgrammingTask/blob/master/06_sandbox_escape_finder.md)
and [general submission instructions](https://github.com/SeekingDream/ProgrammingTask#readme).

The suite includes ten task acceptance checks alongside detector, oracle,
API, configuration, and integration tests. The two environments below
run disjoint selections of the same collected suite.

## Build both images

Open PowerShell in this project directory, with Docker Desktop running Linux
containers:

```powershell
docker build -t sandbox-escape-finder:latest .
docker build -f Dockerfile.test -t sandbox-escape-finder:test .
```

The application image starts the probe CLI. The test image starts pytest and
installs the package through the required editable-install path. Its dependency
versions are constrained by `requirements-test-lock.txt`; runtime and build
requirements are pinned in `pyproject.toml`. The Python base image is pinned by
digest. Rebuild both images after application changes, and rebuild the test
image after test changes.

## Run the full Linux suite in Docker

```powershell
New-Item -ItemType Directory -Force reports | Out-Null
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 sandbox-escape-finder:test 2>&1 | Tee-Object -FilePath reports/pytest-container.txt
$LASTEXITCODE
```

Expected current result: **100 passed, 8 deselected**, exit code **0**.
The deselected tests exercise the Docker backend separately in the next step.
The 100 include all ten checks in `validation/test_task6_requirements.py`.
Running the test image from Docker Desktop also starts this suite; the terminal
command additionally applies the displayed containment and resource settings.

The test container has no host-directory or Docker-socket mount. Networking is
disabled, the root filesystem is read-only, the user is non-root, and workspaces
live in tmpfs. The actual corpus also runs in individual resource-limited
subprocesses inside that container. Controlled toy-sandbox fixtures remain
contained by the outer container.

To select just the ten task checks:

```powershell
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 sandbox-escape-finder:test python -m pytest -q validation/test_task6_requirements.py -p no:cacheprovider
```

Expected: **10 passed**, exit code **0**. These checks also run as part of the
full command; running them separately is useful while changing a requirement.

## Run the Docker-backend tests

This path runs pytest on Windows, and launches a fresh disposable container for
each payload. These selected tests do not execute payloads on the host. The
outer Linux test container does not contain a Docker daemon/CLI or socket.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -c requirements-test-lock.txt -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q -m docker -p no:cacheprovider 2>&1 | Tee-Object -FilePath reports/pytest-docker-backend.txt
$LASTEXITCODE
```

Expected: **8 passed, 100 deselected**, exit code **0**. Together these two
selections cover **108 distinct tests**. Use `-m docker` for the Windows run;
the other dynamic tests require POSIX resource limits and run in Linux.
If a Docker test is skipped, inspect its reason and check the daemon and image
before counting that test as exercised.

## Run the example and save the configured report

```powershell
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 sandbox-escape-finder:latest python -I examples/quickstart.py 2>&1 | Tee-Object -FilePath reports/quickstart.txt
docker run --rm --network none --read-only --tmpfs /tmp:rw,size=64m,mode=1777 --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 1 --pids-limit 64 sandbox-escape-finder:latest python -I -m sandbox_escape_finder.cli --config config/default.json probe --json | Out-File -Encoding utf8 reports/probe.json
$report = Get-Content -Raw reports/probe.json | ConvertFrom-Json
$report.summary
```

Current corpus result: **19 payloads**, **14 statically flagged**,
**14 compile-rejected**, **3 execution-blocked**, **2 benign completions**,
**0 confirmed escapes**, **0 inconclusive**, and **0 static-expectation
mismatches**. The quickstart prints both static findings and dynamic results,
including the required false-positive/negative comparison.

No confirmed RestrictedPython escape is required. Contained toy-sandbox
positive controls independently establish that the oracle detects an effect.
A regression test also confirms that an effect remains confirmed if execution later
raises an exception.

## Requirement-to-evidence map

| Requirement | Evidence |
|---|---|
| AST analysis, at least five named techniques | Seven detectors with positive/negative tests, locations, AST node information, and confidence fields. |
| Required input/output API | `run()` accepts iterable/generator source strings or attributed cases and returns a plain `list[dict]`; `run_report()` is an additional rich API. |
| Callable sandbox and oracle | Importable trusted module-level functions run inside workers. The oracle receives before/result/after, including the original custom sandbox result. Local closures and `__main__` functions are explicitly rejected in isolated modes; the explicitly opted-in controlled mode supports local callables. |
| Real unmodified RestrictedPython | PyPI RestrictedPython 8.5; full corpus exercised through subprocess and Docker workers. |
| Disposable isolated targets | Resource-limited Linux test container plus throwaway worker workspaces; Docker-backend tmpfs positive controls. |
| Automated oracle | Positive marker, benign negative, canary tamper, blocked real sandbox, effect-before-exception, and custom-oracle tests. |
| At least ten catalog-seeded probes | Twelve catalog-derived probes with a [source/adaptation map](CORPUS_SOURCES.md); five additional checks and two benign controls. |
| Custom payloads via config | Acceptance test executes a configured custom case inside a worker. |
| Static/dynamic false positives and negatives | Full-corpus comparison plus a contained confirmed escape with detectors disabled, demonstrating false-negative reporting. |
| Config-driven reproducibility | Seeded order and semantic outcomes checked twice; timings excluded. |
| Thresholds | Inclusive `min_confidence` in [0, 1]; invalid values rejected; dynamic execution still runs. |
| Safe configuration objects | Existing `Config` instances are revalidated, including the in-process opt-in gate. |
| Installation and dependency versions | Docker build tests normal install; test build exercises editable install; direct dependencies/build tools and test dependency constraints pinned. |
| README, API example, results table | Updated README, verified Docker quickstart, saved JSON report and logs. |
| Research understanding | Manual: explain the techniques, guards, oracle scope, architecture, and known limitations. |

Importable hook modules must be present in the worker environment, including the
Docker image when using the Docker backend. Unsupported callables produce a
clear error; there is no silent fallback to the host or another oracle.

The oracle observes the documented workspace effects; this is not a proof of
safety against every possible escape. `builtin_self` and `object_dict` remain
visible static coverage limits and are dynamically rejected. Pure information
leaks and effects outside the watched workspace need an extended oracle.

The validated target is RestrictedPython 8.5; see the README for the
per-payload results and the source map for probe attribution.
