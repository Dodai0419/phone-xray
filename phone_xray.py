#!/usr/bin/env python3
"""phone-xray: see what any Android phone or TV can leak, and switch it off with one-step undo.

Rules and parsers are ported from Verlintas/NOIR (MIT). The plan-first, undo-everything flow
comes from udhaykumarbala/cleanyourtv-app (MIT). Standard library only.
"""
import argparse, html, json, os, re, shlex, subprocess, sys, tempfile, time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent

# ---------- rules (from NOIR Rules.kt / Exposure.kt) ----------
DATA = {
    "ACCESS_FINE_LOCATION": "location", "ACCESS_COARSE_LOCATION": "location", "ACCESS_BACKGROUND_LOCATION": "location",
    "READ_CONTACTS": "contacts", "READ_SMS": "SMS", "RECEIVE_SMS": "SMS", "READ_CALL_LOG": "call log",
    "READ_PHONE_STATE": "device ID", "READ_PRIVILEGED_PHONE_STATE": "device ID",
    "RECORD_AUDIO": "microphone", "CAPTURE_AUDIO_OUTPUT": "microphone", "CAPTURE_VOICE_COMMUNICATION_OUTPUT": "microphone",
    "CAMERA": "camera", "FOREGROUND_SERVICE_MEDIA_PROJECTION": "screen",
    "QUERY_ALL_PACKAGES": "app list", "PACKAGE_USAGE_STATS": "app list",
    "MANAGE_EXTERNAL_STORAGE": "files", "READ_MEDIA_IMAGES": "files", "READ_MEDIA_VIDEO": "files", "READ_EXTERNAL_STORAGE": "files",
    "READ_CALENDAR": "calendar", "GET_ACCOUNTS": "accounts",
}
UPLOAD = re.compile(r"/(report|upload|collect|track|stat|beacon|log)([/?]|$)", re.I)
COMMAND = re.compile(r"/(command|cmd|dispatch|execute|script)([/?]|$)", re.I)


SENSITIVE = {"ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION", "READ_CONTACTS", "READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG",
             "READ_PHONE_STATE", "READ_PRIVILEGED_PHONE_STATE", "RECORD_AUDIO", "CAMERA", "PACKAGE_USAGE_STATS", "QUERY_ALL_PACKAGES",
             "GET_ACCOUNTS", "READ_CALENDAR", "MANAGE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO", "SYSTEM_ALERT_WINDOW",
             "REQUEST_INSTALL_PACKAGES", "FOREGROUND_SERVICE_MEDIA_PROJECTION", "CAPTURE_AUDIO_OUTPUT",
             "CAPTURE_VOICE_COMMUNICATION_OUTPUT", "WRITE_SECURE_SETTINGS"}


def score(perms, urls, is_system=False, debuggable=False):
    """perms holds sensitive permissions only; normal ones never add points."""
    s = len(perms)
    s += 2 * ("QUERY_ALL_PACKAGES" in perms) + 3 * ("READ_PRIVILEGED_PHONE_STATE" in perms)
    s += 4 * ("FOREGROUND_SERVICE_MEDIA_PROJECTION" in perms)
    s += 2 * bool(is_system) + 2 * bool(debuggable)
    s += 2 * any(COMMAND.search(u) for u in urls) + 3 * any(UPLOAD.search(u) for u in urls)
    return s


def data_types(perms):
    return sorted({DATA[p] for p in perms if p in DATA})


def host_of(url):
    if "://" not in url:
        return None
    host = url.split("://", 1)[1].split("/")[0].split(":")[0].lower()
    return host if "." in host else None


def upload_hosts(urls):
    return sorted({h for h in (host_of(u) for u in urls if UPLOAD.search(u)) if h and not is_ignored(h)})


def leaks(perms, urls):
    """Data the app can read joined with hosts it can upload to. Capability alone is not a leak."""
    hosts = upload_hosts(urls)
    return {d: hosts for d in data_types(perms)} if hosts else {}


# ---------- domain tiers (from NOIR Domains.kt) ----------
IGNORED = {"schemas.android.com", "www.w3.org", "w3.org", "xmlpull.org", "jakarta.apache.org", "apache.org", "ns.adobe.com",
           "xml.apache.org", "java.sun.com", "www.bea.com", "github.com", "githubusercontent.com", "codeberg.org",
           "schemas.microsoft.com", "developer.android.com", "issuetracker.google.com", "youtrack.jetbrains.com", "localhost"}
FUNCTIONAL_LABELS = {"push", "xmpush", "mipush", "fcm", "gcm", "mtalk", "firebase", "jpush", "getui", "account", "accounts", "login",
                     "passport", "oauth", "sso", "signin", "update", "updater", "ota", "download", "dl", "pay", "mipay", "alipay",
                     "unionpay", "wallet", "play", "vending", "market", "appstore", "cloud", "micloud", "icloud", "backup", "sync", "connect"}
FUNCTIONAL_SUBS = ("googleapis", "gstatic", "oppomobile", "heytapmobi")
BLOCK_EXACT = {"log", "logs", "ads", "ad", "mon", "px", "ut", "mam", "up4"}
BLOCK_SUBS = ("applog", "errlog", "errnewlog", "rtlog", "rtapplog", "uplog", "apmlog", "aegis-log", "report", "monitor", "analytics",
              "beacon", "track", "collect", "crash", "metrics", "telemetry", "umeng", "appsflyer", "adjust", "oceanengine", "zijieapi",
              "qplus", "snssdk", "cnzz", "growingio", "sensorsdata", "mixpanel", "amplitude", "pangle", "sigmob", "adashx", "pingma",
              "talkingdata", "bugtrace", "huatuo", "apmplus", "coverage", "zxid", "oaid", "wkanx", "videoreport")
TEST_LABELS = {"test", "testing", "staging", "stg", "dev", "daily", "preview", "sandbox"}


def is_test_host(host):
    return any(l in TEST_LABELS for l in host.lower().split("."))


def is_ignored(host):
    h = host.lower()
    return h in IGNORED or bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", h)) or (":" in h and bool(re.fullmatch(r"[0-9a-f:]+", h)))


def classify_domain(host):
    labels = host.lower().split(".")
    if any(l in TEST_LABELS for l in labels):
        return "review"
    if any(l in FUNCTIONAL_LABELS for l in labels) or any(s in host for s in FUNCTIONAL_SUBS):
        return "functional"
    if any(l in BLOCK_EXACT for l in labels) or any(s in l for l in labels for s in BLOCK_SUBS):
        return "tracker"
    # stat / stats / statistic are trackers; status is not
    if any(l.startswith("stat") and not l.startswith("status") for l in labels):
        return "tracker"
    return "review"


def export_domains(apps):
    out = {"tracker": set(), "review": set(), "functional": set()}
    for a in apps:
        for h in upload_hosts(a["urls"]):
            if not is_test_host(h):
                out[classify_domain(h)].add(h)
    return {k: sorted(v) for k, v in out.items()}


# ---------- categories (from NOIR Classifier.kt, trimmed to what the plan needs) ----------
TELEMETRY = re.compile(r"(^|[./_-])(analytics|track|tracker|tracking|stat|stats|beacon|telemetry|misight|onetrack|logging)([./_-]|$)")
ADS = re.compile(r"(^|[./_-])(ads?|advert|advertising|doubleclick|pangle|sigmob)([./_-]|$)")
KNOWN = {"com.miui.analytics": "telemetry", "com.miui.misightservice": "telemetry", "com.xiaomi.security.onetrack": "telemetry",
         "com.miui.powerinsight": "telemetry", "com.miui.securitycenter": "security", "com.miui.guardprovider": "security",
         "com.miui.systemadsolution": "ads", "com.xiaomi.market": "store", "com.android.vending": "store", "com.xiaomi.xmsf": "push",
         "com.android.systemui": "system", "com.tencent.mm": "social", "com.tencent.mobileqq": "social",
         "com.eg.android.alipaygphone": "finance", "com.taobao.taobao": "shopping", "tv.danmaku.bili": "media", "com.google.android.youtube": "media"}
KEYWORDS = [("store", ("market", "vending", "appstore")), ("finance", ("pay", "wallet", "unionpay", ".bank")),
            ("media", ("netflix", "spotify", "music", "video", "youtube")), ("social", ("whatsapp", "instagram", "telegram", "facebook"))]


def category(pkg, urls=(), is_system=False):
    name = pkg.lower()
    if name in KNOWN:
        return KNOWN[name]
    for cat, keys in KEYWORDS:
        if any(k in name for k in keys):
            return cat
    both = name + " " + " ".join(urls).lower()
    if TELEMETRY.search(both):
        return "telemetry"
    if ADS.search(both):
        return "ads"
    return "system" if is_system else "other"


# ---------- dumpsys parser (from NOIR Dumpsys.kt) ----------
_PKG = re.compile(r"^  Package \[([^\]]+)]")
_SHARED = re.compile(r"^  SharedUser \[([^\]]+)]")
_SHARED_USER = re.compile(r"^sharedUser=SharedUserSetting\{[0-9a-f]+ ([^/]+)/")
_PKG_SETTING = re.compile(r"PackageSetting\{[0-9a-f]+ ([^/]+)/")
_GRANTED = re.compile(r"^android\.permission\.([A-Z0-9_]+): granted=true(?:[,;].*)?$")


def _blank():
    return {"flags": "", "app_id": "", "installer": None, "shared_user": None, "perms": set()}


def parse_dumpsys(text):
    pkgs, cur, shared, in_shared = {}, None, None, False
    members, sperms, sapp = {}, {}, {}
    for line in text.splitlines():
        if line.startswith("Shared users:"):
            in_shared, cur, shared = True, None, None
            continue
        s = line.strip()
        if not in_shared:
            m = _PKG.match(line)
            if m:
                cur = pkgs.setdefault(m[1], _blank())  # duplicate blocks merge
            elif cur is not None:
                if s.startswith("appId=") and not cur["app_id"]:
                    cur["app_id"] = s[6:]
                elif s.startswith("flags=[") and not cur["flags"]:
                    cur["flags"] = s
                elif s.startswith("installerPackageName=") and cur["installer"] is None:
                    v = s.split("=", 1)[1]
                    cur["installer"] = None if v == "null" else v
                elif s.startswith("sharedUser=") and cur["shared_user"] is None:
                    m = _SHARED_USER.match(s)
                    cur["shared_user"] = m and m[1]
                else:
                    m = _GRANTED.match(s)
                    if m:
                        cur["perms"].add(m[1])
        else:
            m = _SHARED.match(line)
            if m:
                shared = m[1]
                members.setdefault(shared, [])
                sperms.setdefault(shared, set())
            elif shared:
                if s.startswith("appId="):
                    sapp[shared] = s[6:]
                else:
                    m = _PKG_SETTING.search(s)
                    if m:
                        members[shared].append(m[1])
                    m = _GRANTED.match(s)
                    if m:
                        sperms[shared].add(m[1])
    for su, names in members.items():
        for name in names:
            e = pkgs.setdefault(name, _blank())
            e["perms"] |= sperms[su]
            if not e["app_id"] and su in sapp:
                e["app_id"] = sapp[su]
            if not e["flags"] and sapp.get(su) == "1000":
                e["flags"] = "SYSTEM"
    return pkgs


# ---------- plan: nothing changes until --apply, and every change has an undo ----------
NEVER_TOUCH = {"android", "com.android.systemui", "com.android.settings", "com.android.phone", "com.android.vending",
               "com.google.android.gms", "com.google.android.gsf", "com.google.android.tvlauncher", "com.miui.home",
               "com.miui.securitycenter", "com.miui.guardprovider", "com.xiaomi.xmsf"}
MEDIA_KEEP = {"com.miui.screenrecorder", "com.android.chrome", "com.google.android.youtube", "com.tencent.mm", "com.tencent.mobileqq",
              "tv.danmaku.bili"}
# shortcut: a short list of well-known packages, no per-brand TV lists; upgrade by loading community lists per device model.
AD_PACKAGES = {"com.miui.analytics", "com.miui.systemadsolution", "com.miui.msa.global", "com.miui.misightservice",
               "com.facebook.appmanager", "com.facebook.services", "com.facebook.system"}


def advise(apps):
    out = []

    def add(pkg, action, risk, why, do="", undo=""):
        out.append({"pkg": pkg, "action": action, "risk": risk, "why": why, "do": do, "undo": undo, "safe": bool(do)})

    for a in apps:
        p = a["pkg"]
        if p in NEVER_TOUCH:
            continue
        cat, sysapp = a["category"], a["system"]
        if ("FOREGROUND_SERVICE_MEDIA_PROJECTION" in a["perms"] and p not in MEDIA_KEEP and sysapp
                and (cat in ("security", "telemetry") or upload_hosts(a["urls"]))):
            add(p, "block screen capture", "MED", "system component that can record the screen and has an upload endpoint",
                f"appops set {p} PROJECT_MEDIA ignore", f"appops set {p} PROJECT_MEDIA default")
        if "PACKAGE_USAGE_STATS" in a["perms"] and cat == "telemetry" and sysapp:
            add(p, "block usage stats", "MED", "telemetry app can read which apps you use",
                f"appops set {p} GET_USAGE_STATS ignore", f"appops set {p} GET_USAGE_STATS default")
        if p in AD_PACKAGES:
            add(p, "switch off", "MED", "known ad or telemetry package", f"pm disable-user --user 0 {p}", f"pm enable {p}")
        elif cat in ("telemetry", "ads"):
            add(p, "review", "HIGH" if sysapp else "MED",
                "telemetry or ads system component; block its hosts at DNS" if sysapp else "heavy telemetry or ads; decide yourself")
        if len(upload_hosts(a["urls"])) >= 2 and cat in ("telemetry", "ads"):
            add(p, "block at DNS", "LOW", "several upload hosts; block them at DNS instead of removing the app")
    rank = {"HIGH": 0, "MED": 1, "LOW": 2}
    return sorted(out, key=lambda r: (rank[r["risk"]], r["pkg"], r["action"]))


# ---------- device access ----------
SCAN_SH = r"""#!/system/bin/sh
TMP=/data/local/tmp/xray_dex.bin
while read p f; do
  : > $TMP
  for d in classes.dex classes2.dex classes3.dex classes4.dex classes5.dex classes6.dex classes7.dex classes8.dex; do
    unzip -p "$f" "$d" 2>/dev/null >> $TMP
  done
  if [ -s $TMP ]; then
    u=$(strings < $TMP | grep -oE 'https?://[A-Za-z0-9._~:/?#@!&()*+,;=%-]+' | sort -u | head -400 | tr '\n' ' ')
    [ -n "$u" ] && echo "R $p|$u"
  fi
  rm -f $TMP
done < /data/local/tmp/xray_targets.txt
echo "#DONE"
"""


class Adb:
    def __init__(self, adb="adb", serial=None):
        # posix=False keeps Windows backslashes, but also keeps the quotes around a path
        self.cmd = [p.strip('"') for p in shlex.split(adb, posix=os.name != "nt")] + (["-s", serial] if serial else [])

    def run(self, *args, check=True):
        try:
            r = subprocess.run(self.cmd + list(args), capture_output=True, text=True, errors="replace", timeout=600)
        except FileNotFoundError:
            sys.exit("adb not found. Install Android platform-tools or pass --adb <path>.")
        if check and r.returncode:
            raise RuntimeError(f"adb {' '.join(args)} failed: {(r.stderr or r.stdout).strip()}")
        return r.stdout

    def shell(self, command):
        return self.run("shell", command)


def parse_packages(text):
    paths = {}
    for line in text.splitlines():
        if line.startswith("package:") and "=" in line:
            path, pkg = line[8:].rsplit("=", 1)
            if pkg.strip():
                paths[pkg.strip()] = path
    return paths


def parse_scan(text):
    urls = {}
    for line in text.splitlines():
        if line.startswith("R ") and "|" in line:
            pkg, found = line[2:].split("|", 1)
            urls[pkg] = found.split()
    return urls


def collect(adb):
    """Read the device. Only a few KB of URL strings leave it; APKs stay where they are."""
    dump, paths = adb.shell("dumpsys package"), parse_packages(adb.shell("pm list packages -f"))
    # toybox `which` exits non-zero when one tool is missing, so only its output counts
    tools = adb.run("shell", "which unzip strings", check=False)
    scan, note = "", ""
    if "unzip" in tools and "strings" in tools:
        with tempfile.TemporaryDirectory() as d:
            sh, tg = Path(d, "scan.sh"), Path(d, "targets.txt")
            sh.write_bytes(SCAN_SH.encode())
            tg.write_bytes("".join(f"{p} {f}\n" for p, f in paths.items()).encode())
            adb.run("push", str(sh), "/data/local/tmp/xray_scan.sh")
            adb.run("push", str(tg), "/data/local/tmp/xray_targets.txt")
        scan = adb.shell("sh /data/local/tmp/xray_scan.sh")
        adb.shell("rm -f /data/local/tmp/xray_scan.sh /data/local/tmp/xray_targets.txt")
        if "#DONE" not in scan:
            note = "endpoint scan did not finish; endpoints may be partial"
    else:
        note = "device has no unzip/strings; report covers permissions only, not endpoints"
    return dump, paths, scan, note


def build_apps(dump, paths, scan):
    meta, urls = parse_dumpsys(dump), parse_scan(scan)
    apps = []
    for pkg, m in meta.items():
        sensitive = m["perms"] & SENSITIVE
        if pkg not in paths or "INTERNET" not in m["perms"] or not sensitive:
            continue
        u = urls.get(pkg, [])
        system = "SYSTEM" in m["flags"]
        debuggable = "DEBUGGABLE" in m["flags"]
        perms = sorted(sensitive)
        apps.append({"pkg": pkg, "system": system, "debuggable": debuggable, "installer": m["installer"], "shared_user": m["shared_user"],
                     "perms": perms, "urls": u, "category": category(pkg, u, system), "score": score(perms, u, system, debuggable),
                     "data": data_types(perms), "leaks": leaks(perms, u)})
    return sorted(apps, key=lambda a: (-a["score"], a["pkg"]))


# ---------- output ----------
def rollback_text(plan):
    lines = ["# phone-xray rollback. Run: python phone_xray.py --undo <this file>"]
    return "\n".join(lines + [r["undo"] for r in plan if r["safe"]]) + "\n"


def apply_plan(adb, plan, rollback_path):
    # The undo file is written first, so a failure half way still leaves a way back.
    Path(rollback_path).write_text(rollback_text(plan), encoding="utf-8")
    done, failed = 0, []
    for r in plan:
        if not r["safe"]:
            continue
        try:
            adb.shell(r["do"])
            done += 1
        except RuntimeError as e:
            failed.append(f"{r['pkg']}: {e}")
    return done, failed


def undo(adb, path):
    lines = [l for l in Path(path).read_text(encoding="utf-8").splitlines() if l and not l.startswith("#")]
    # Check every line first, so a bad file changes nothing.
    for line in lines:
        if not re.fullmatch(r"pm enable [\w.]+|appops set [\w.]+ \w+ default", line):
            sys.exit(f"refusing to run unexpected line in rollback file: {line}")
    done, failed = 0, []
    for line in lines:
        try:
            adb.shell(line)
            done += 1
        except RuntimeError as e:
            failed.append(str(e))
    return done, failed


def _chip(text, color):
    return f'<span style="background:{color};color:#0b0f14;border-radius:4px;padding:1px 7px;margin:1px 3px 1px 0;display:inline-block;font-size:12px;font-weight:600">{html.escape(text)}</span>'


CHIP = {"location": "#f59e8b", "SMS": "#f59e8b", "microphone": "#f59e8b", "camera": "#f59e8b", "screen": "#f59e8b", "contacts": "#f59e8b", "call log": "#f59e8b"}


def summary(apps, plan):
    d = export_domains(apps)
    return {"apps": len(apps), "leaky": sum(bool(a["leaks"]) for a in apps), "trackers": len(d["tracker"]), "functional": len(d["functional"]),
            "review": len(d["review"]), "safe_actions": sum(r["safe"] for r in plan), "manual": sum(not r["safe"] for r in plan)}


def render_html(apps, plan, label, note=""):
    s, d = summary(apps, plan), export_domains(apps)
    data = Counter(k for a in apps for k in a["leaks"])
    stat = lambda n, t, c="#e6edf3": f'<div class="s"><b style="color:{c}">{n}</b><span>{t}</span></div>'
    rows = "".join(
        f'<tr><td class="n">{a["score"]}</td><td><code>{html.escape(a["pkg"])}</code>{" <i>system</i>" if a["system"] else ""}</td>'
        f'<td>{"".join(_chip(k, CHIP.get(k, "#a7c7e7")) for k in a["data"]) or "-"}</td>'
        f'<td>{"<br>".join(html.escape(h) for h in upload_hosts(a["urls"])[:3]) or "-"}</td></tr>'
        for a in apps[:14])
    prows = "".join(
        f'<tr><td>{r["risk"]}</td><td><code>{html.escape(r["pkg"])}</code></td><td>{html.escape(r["action"])}</td><td>{html.escape(r["why"])}</td>'
        f'<td>{"<code>" + html.escape(r["undo"]) + "</code>" if r["safe"] else "manual"}</td></tr>' for r in plan[:14])
    who = "".join(f"<li><b>{html.escape(k)}</b> can reach upload hosts in {v} app{'s' if v > 1 else ''}</li>" for k, v in data.most_common(6))
    return f"""<!doctype html><meta charset="utf-8"><title>phone-xray: {html.escape(label)}</title><style>
body{{margin:0;background:#0b0f14;color:#e6edf3;font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif;padding:28px;max-width:1120px}}
h1{{font-size:24px;margin:0 0 2px}} h2{{font-size:15px;margin:26px 0 8px;color:#9fb3c8;text-transform:uppercase;letter-spacing:.06em}}
.sub{{color:#8b9bab;margin-bottom:18px}} .g{{display:flex;gap:10px;flex-wrap:wrap}} .s{{background:#141b23;border:1px solid #243140;border-radius:8px;padding:10px 16px;min-width:120px}}
.s b{{font-size:26px;display:block}} .s span{{color:#8b9bab;font-size:12px}} table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #1d2733;padding:6px 8px;text-align:left;vertical-align:top}}
th{{color:#8b9bab;font-weight:500;font-size:12px}} code{{font:12px ui-monospace,Consolas,monospace;color:#c9d7e4}} i{{color:#8b9bab;font-size:11px}} .n{{font-weight:700;color:#f59e8b}}
.cols{{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}} .c{{background:#141b23;border:1px solid #243140;border-radius:8px;padding:10px 14px}} .c code{{display:block}}
</style><h1>phone-xray report</h1><div class="sub">{html.escape(label)}{" &middot; " + html.escape(note) if note else ""}</div>
<div class="g">{stat(s["apps"], "apps read")}{stat(s["leaky"], "can read data and upload it", "#f59e8b")}{stat(s["trackers"], "tracker hosts", "#f59e8b")}{stat(s["functional"], "do-not-block hosts", "#7ee2a8")}{stat(s["safe_actions"], "reversible fixes", "#7ee2a8")}{stat(s["manual"], "need your decision", "#f2cc60")}</div>
<h2>What can leave this device</h2><ul>{who or "<li>No app pairs readable data with an upload endpoint.</li>"}</ul>
<h2>Riskiest apps</h2><table><tr><th>score</th><th>package</th><th>can read</th><th>uploads to</th></tr>{rows}</table>
<h2>The plan (nothing has changed yet)</h2><table><tr><th>risk</th><th>package</th><th>action</th><th>why</th><th>undo</th></tr>{prows}</table>
<h2>Hosts, split so a blocklist leaves push and login alone</h2><div class="cols">
<div class="c"><b style="color:#f59e8b">Safe to block</b>{"".join(f"<code>{html.escape(h)}</code>" for h in d["tracker"]) or " none"}</div>
<div class="c"><b style="color:#f2cc60">You decide</b>{"".join(f"<code>{html.escape(h)}</code>" for h in d["review"]) or " none"}</div>
<div class="c"><b style="color:#7ee2a8">Do not block</b>{"".join(f"<code>{html.escape(h)}</code>" for h in d["functional"]) or " none"}</div></div>
"""


def write_report(apps, plan, out, label, note=""):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(render_html(apps, plan, label, note), encoding="utf-8")
    (out / "report.json").write_text(json.dumps({"label": label, "note": note, "summary": summary(apps, plan), "apps": apps, "plan": plan,
                                                 "hosts": export_domains(apps)}, indent=1), encoding="utf-8")
    d = export_domains(apps)
    (out / "blocklist.txt").write_text("\n".join(d["tracker"]) + "\n", encoding="utf-8")
    (out / "plan.txt").write_text("\n".join(f"adb shell {r['do']}" for r in plan if r["safe"]) + "\n", encoding="utf-8")
    (out / "rollback.txt").write_text(rollback_text(plan), encoding="utf-8")


def print_summary(apps, plan, out):
    s = summary(apps, plan)
    print(f"{s['apps']} apps read, {s['leaky']} can read personal data and upload it")
    print(f"{s['trackers']} tracker hosts safe to block, {s['functional']} hosts left alone")
    for a in apps[:5]:
        print(f"  {a['score']:>3}  {a['pkg']}  {', '.join(a['data']) or '-'}")
    print(f"plan: {s['safe_actions']} reversible fixes, {s['manual']} for you to decide. Nothing changed yet.")
    print(f"report: {Path(out) / 'report.html'}")


def load_fixture(d):
    d = Path(d)
    return [(d / n).read_text(encoding="utf-8") for n in ("dumpsys.txt", "packages.txt", "scan.txt")]


def main(argv=None):
    ap = argparse.ArgumentParser(description="See what any Android phone or TV can leak, and switch it off with one-step undo.")
    ap.add_argument("--demo", action="store_true", help="run on the bundled simulated phone; needs no device")
    ap.add_argument("--adb", default="adb", help="adb command")
    ap.add_argument("-s", "--serial", help="device serial, or ip:port for a TV")
    ap.add_argument("--connect", metavar="IP[:PORT]", help="run adb connect first, for a TV on your Wi-Fi")
    ap.add_argument("--out", default="xray-report")
    ap.add_argument("--apply", action="store_true", help="run the reversible fixes; writes rollback.txt first")
    ap.add_argument("--undo", metavar="FILE", help="replay a rollback file")
    a = ap.parse_args(argv)
    adb = Adb(a.adb, a.serial)
    if a.undo:
        done, failed = undo(adb, a.undo)
        print(f"restored {done} settings")
        for f in failed:
            print("  failed:", f)
        return 1 if failed else 0
    if a.connect:
        print(adb.run("connect", a.connect).strip())
        a.serial = a.serial or a.connect
        adb = Adb(a.adb, a.serial)
    t = time.perf_counter()
    if a.demo:
        dump, pk, scan = load_fixture(HERE / "examples" / "simulated-phone")
        paths, note, label = parse_packages(pk), "", "simulated phone (bundled fixture, not a real device)"
    else:
        try:
            dump, paths, scan, note = collect(adb)
        except RuntimeError as e:
            sys.exit(f"{e}\nEnable USB debugging, plug in the device and accept the prompt, or use --connect for a TV.")
        label = a.serial or "connected device"
    apps = build_apps(dump, paths, scan)
    plan = advise(apps)
    write_report(apps, plan, a.out, label, note)
    print_summary(apps, plan, a.out)
    print(f"took {time.perf_counter() - t:.3f}s")
    if a.apply:
        if a.demo:
            sys.exit("--apply needs a real device")
        rb = Path(a.out) / "rollback.txt"
        done, failed = apply_plan(adb, plan, rb)
        print(f"applied {done} fixes. Undo: python phone_xray.py --undo {rb}")
        for f in failed:
            print("  failed:", f)
    return 0


if __name__ == "__main__":
    sys.exit(main())
