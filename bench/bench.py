"""Time the audit (parse, classify, plan, write report) on the bundled fixture. Usage: python bench/bench.py"""
import statistics, sys, tempfile, time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import phone_xray as x

d, p, s = x.load_fixture(x.HERE / "examples" / "simulated-phone")
runs = []
with tempfile.TemporaryDirectory() as out:
    for _ in range(50):
        t = time.perf_counter()
        apps = x.build_apps(d, x.parse_packages(p), s)
        x.write_report(apps, x.advise(apps), out, "bench")
        runs.append((time.perf_counter() - t) * 1000)
print(f"audit {len(apps)} apps: median {statistics.median(runs):.2f} ms, min {min(runs):.2f}, max {max(runs):.2f} (50 runs)")
