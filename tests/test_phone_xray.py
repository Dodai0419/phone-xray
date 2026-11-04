import json, shutil, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import phone_xray as x

ROOT = Path(__file__).resolve().parent.parent
FAKE_ADB = r'''
import sys
args = sys.argv[1:]
open(sys.argv[0] + ".log", "a").write(" ".join(args) + "\n")
fx = %r
if args[0] == "push": sys.exit(0)
if args[0] == "connect": print("connected"); sys.exit(0)
cmd = args[1] if args[0] == "shell" else ""
out = {"dumpsys package": "dumpsys.txt", "pm list packages -f": "packages.txt", "sh /data/local/tmp/xray_scan.sh": "scan.txt"}.get(cmd)
if out: sys.stdout.write(open(fx + "/" + out, encoding="utf-8").read())
elif cmd.startswith("which"): print("/system/bin/unzip\n/system/bin/strings")
elif "BOOM" in cmd: sys.exit(1)
'''


class DumpsysVectors(unittest.TestCase):
    """Vectors ported from NOIR DumpsysTest.kt."""

    def test_merges_duplicate_blocks(self):
        t = "\n".join(["  Package [com.example.app] (aaa):", "    appId=10200", "    flags=[ HAS_CODE ]", "    installerPackageName=null",
                       "  Package [com.example.app] (bbb):", "    versionName=1.2.3", "    android.permission.INTERNET: granted=true"])
        m = x.parse_dumpsys(t)["com.example.app"]
        self.assertIn("INTERNET", m["perms"])
        self.assertEqual(m["app_id"], "10200")
        self.assertNotIn("SYSTEM", m["flags"])

    def test_shared_uid_permissions(self):
        t = "\n".join(["  Package [com.miui.securitycenter] (abc):", "    appId=1000", "    sharedUser=SharedUserSetting{def android.uid.system/1000}",
                       "    flags=[ SYSTEM HAS_CODE ]", "  Package [com.example.userapp] (123):", "    appId=10500", "    flags=[ HAS_CODE ]", "",
                       "Shared users:", "  SharedUser [android.uid.system] (def):", "    appId=1000", "    Packages",
                       "      PackageSetting{abc com.miui.securitycenter/1000}", "    install permissions:",
                       "      android.permission.INTERNET: granted=true", "      android.permission.QUERY_ALL_PACKAGES: granted=true"])
        p = x.parse_dumpsys(t)
        self.assertIn("QUERY_ALL_PACKAGES", p["com.miui.securitycenter"]["perms"])
        self.assertEqual(p["com.miui.securitycenter"]["shared_user"], "android.uid.system")
        self.assertNotIn("QUERY_ALL_PACKAGES", p["com.example.userapp"]["perms"])

    def test_denied_is_not_granted(self):
        t = "  Package [a.b] (1):\n    android.permission.CAMERA: granted=false\n    android.permission.READ_SMS: granted=true, flags=[ X ]"
        self.assertEqual(x.parse_dumpsys(t)["a.b"]["perms"], {"READ_SMS"})


class DomainVectors(unittest.TestCase):
    """Vectors ported from NOIR DomainsTest.kt."""

    def test_tiers(self):
        for h in ("applog.snssdk.com", "tracking.miui.com", "rttgpsreport.map.qq.com", "stat.api.tpns.tencent.com", "stage-data.ads.example.com"):
            self.assertEqual(x.classify_domain(h), "tracker", h)
        for h in ("api.push.oppomobile.com", "android.googleapis.com", "play.googleapis.com", "upload-data-api.xmpush.xiaomi.net",
                  "connect.rom.miui.com", "statusapi.micloud.xiaomi.net"):
            self.assertEqual(x.classify_domain(h), "functional", h)
        for h in ("api.bilibili.com", "instagram.com", "api.sec.miui.com", "staging-notify.sec.miui.com", "status.example.com"):
            self.assertEqual(x.classify_domain(h), "review", h)

    def test_ignored(self):
        for h in ("schemas.android.com", "www.w3.org", "127.0.0.1", "183.36.108.226"):
            self.assertTrue(x.is_ignored(h), h)
        self.assertFalse(x.is_ignored("api.bilibili.com"))

    def test_export_drops_test_hosts(self):
        app = {"urls": ["https://applog.snssdk.com/upload", "https://api.push.oppomobile.com/upload", "https://api.bilibili.com/upload",
                        "https://log.testing.amap.com/upload", "http://127.0.0.1:8080/report"]}
        self.assertEqual(x.export_domains([app]), {"tracker": ["applog.snssdk.com"], "review": ["api.bilibili.com"], "functional": ["api.push.oppomobile.com"]})


class ExposureAndRules(unittest.TestCase):
    """Vectors ported from NOIR ExposureTest.kt and ClassifierTest.kt."""

    def test_capability_alone_is_not_a_leak(self):
        self.assertEqual(x.leaks(["ACCESS_FINE_LOCATION"], ["https://api.example.com/config"]), {})

    def test_data_joined_with_hosts(self):
        l = x.leaks(["ACCESS_FINE_LOCATION", "READ_CONTACTS"], ["https://a.example.com/upload", "https://b.example.com/collect"])
        self.assertEqual(set(l), {"location", "contacts"})
        self.assertEqual(l["location"], ["a.example.com", "b.example.com"])

    def test_host_of(self):
        self.assertEqual(x.host_of("https://tracking.example.com:8443/collect?x=1"), "tracking.example.com")

    def test_categories(self):
        self.assertEqual(x.category("com.miui.analytics"), "telemetry")
        self.assertEqual(x.category("com.android.statementservice", is_system=True), "system")
        self.assertEqual(x.category("com.qti.qualcomm.datastatusnotification", is_system=True), "system")
        self.assertEqual(x.category("com.example.unknown", ["https://tracking.example.com/track/v1"]), "telemetry")
        self.assertEqual(x.category("com.unknown.user"), "other")

    def test_score_rewards_endpoints(self):
        base = x.score(["INTERNET", "READ_SMS"], [])
        self.assertGreater(x.score(["INTERNET", "READ_SMS"], ["https://a.example.com/upload"]), base)
        self.assertGreater(x.score(["INTERNET", "READ_SMS"], ["https://a.example.com/api/command"]), base)


class Plan(unittest.TestCase):
    def setUp(self):
        d, p, s = x.load_fixture(ROOT / "examples" / "simulated-phone")
        self.apps = x.build_apps(d, x.parse_packages(p), s)
        self.plan = x.advise(self.apps)

    def test_never_touches_core_packages(self):
        self.assertFalse({r["pkg"] for r in self.plan} & x.NEVER_TOUCH)

    def test_every_automatic_fix_has_an_undo(self):
        safe = [r for r in self.plan if r["safe"]]
        self.assertGreater(len(safe), 2)
        for r in safe:
            self.assertTrue(r["undo"])
            self.assertNotIn("uninstall", r["do"])

    def test_undo_matches_action(self):
        r = next(r for r in self.plan if r["do"].startswith("pm disable-user"))
        self.assertEqual(r["undo"], f"pm enable {r['pkg']}")

    def test_keeps_screen_recorder_exception(self):
        self.assertFalse([r for r in self.plan if r["pkg"] == "com.android.systemui"])

    def test_rollback_written_before_apply_and_replayed(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        fake = d / "fake_adb.py"
        fake.write_text(FAKE_ADB % str(ROOT / "examples" / "simulated-phone"), encoding="utf-8")
        adb_cmd = f'"{sys.executable}" "{fake}"'
        self.assertEqual(x.main(["--adb", adb_cmd, "--out", str(d / "o"), "--apply"]), 0)
        log = Path(str(fake) + ".log").read_text(encoding="utf-8")
        self.assertIn("shell dumpsys package", log)
        self.assertIn("pm disable-user --user 0 com.miui.analytics", log)
        report = json.loads((d / "o" / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["summary"]["apps"], 11)
        self.assertEqual(x.main(["--adb", adb_cmd, "--undo", str(d / "o" / "rollback.txt")]), 0)
        log = Path(str(fake) + ".log").read_text(encoding="utf-8")
        self.assertIn("pm enable com.miui.analytics", log)

    def test_undo_refuses_foreign_commands(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        (d / "r.txt").write_text("rm -rf /sdcard\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            x.undo(x.Adb("adb"), d / "r.txt")

    def test_failed_fix_does_not_stop_the_rest(self):
        class A:
            calls = []
            def shell(self, c):
                self.calls.append(c)
                if "boom" in c:
                    raise RuntimeError("x")
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        plan = [{"pkg": "boom", "do": "pm disable-user --user 0 boom", "undo": "pm enable boom", "safe": True},
                {"pkg": "ok", "do": "pm disable-user --user 0 ok", "undo": "pm enable ok", "safe": True}]
        done, failed = x.apply_plan(A(), plan, d / "r.txt")
        self.assertEqual((done, len(failed)), (1, 1))
        self.assertIn("pm enable boom", (d / "r.txt").read_text(encoding="utf-8"))


class NoirRules(unittest.TestCase):
    """NOIR Main.kt keeps only INTERNET + sensitive + known-path apps and scores sensitive permissions only."""

    @staticmethod
    def dump(pkg, *perms):
        lines = [f"  Package [{pkg}] (1):", "    flags=[ HAS_CODE ]"] + [f"    android.permission.{p}: granted=true" for p in perms]
        return "\n".join(lines) + "\n"

    def test_normal_permissions_do_not_inflate_the_score(self):
        normal = ["INTERNET", "VIBRATE", "WAKE_LOCK", "ACCESS_NETWORK_STATE", "RECEIVE_BOOT_COMPLETED", "FOREGROUND_SERVICE"]
        apps = x.build_apps(self.dump("a.b", *normal, "CAMERA", "READ_SMS"), {"a.b": "/p.apk"}, "")
        self.assertEqual(apps[0]["score"], 2)
        self.assertEqual(apps[0]["perms"], ["CAMERA", "READ_SMS"])

    def test_candidate_filter(self):
        d = self.dump("no.net", "CAMERA") + self.dump("no.sens", "INTERNET", "VIBRATE") + self.dump("no.path", "INTERNET", "CAMERA") + self.dump("ok.app", "INTERNET", "CAMERA")
        apps = x.build_apps(d, {"no.net": "/a", "no.sens": "/b", "ok.app": "/c"}, "")
        self.assertEqual([a["pkg"] for a in apps], ["ok.app"])


class DeviceFailures(unittest.TestCase):
    def fake(self, body):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        f = d / "fake_adb.py"
        f.write_text(body, encoding="utf-8")
        return d, f'"{sys.executable}" "{f}"', Path(str(f) + ".log")

    def test_probe_exit_code_is_ignored_and_report_is_permissions_only(self):
        fx = str(ROOT / "examples" / "simulated-phone")
        body = FAKE_ADB.replace(r'print("/system/bin/unzip\n/system/bin/strings")', 'print("/system/bin/unzip"); sys.exit(1)')
        d, adb, _ = self.fake(body % fx)
        self.assertEqual(x.main(["--adb", adb, "--out", str(d / "o")]), 0)
        report = json.loads((d / "o" / "report.json").read_text(encoding="utf-8"))
        self.assertIn("permissions only", report["note"])

    def test_undo_keeps_going_and_reports_failures(self):
        d, adb, log = self.fake(FAKE_ADB % "")
        rb = d / "r.txt"
        rb.write_text("# rollback\npm enable BOOM.one\npm enable ok.two\nappops set ok.three PROJECT_MEDIA default\n", encoding="utf-8")
        self.assertEqual(x.main(["--adb", adb, "--undo", str(rb)]), 1)
        sent = log.read_text(encoding="utf-8")
        self.assertIn("pm enable ok.two", sent)
        self.assertIn("appops set ok.three PROJECT_MEDIA default", sent)

    def test_undo_checks_the_whole_file_before_running_anything(self):
        d, adb, log = self.fake(FAKE_ADB % "")
        rb = d / "r.txt"
        rb.write_text("pm enable ok.one\nrm -rf /sdcard\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            x.main(["--adb", adb, "--undo", str(rb)])
        self.assertFalse(log.exists())


if __name__ == "__main__":
    unittest.main()
