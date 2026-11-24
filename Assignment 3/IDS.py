#!/usr/bin/env python3
"""
CSCI262 System Security - Assignment 3
Email system event modeller & intrusion detection system (IDS)

Usage:   python IDS.py Events.txt Stats.txt Days [--seed N]

Components
  1. Initial input     - parse + validate Events.txt / Stats.txt
  2. Activity engine   - generate events for N days and write a human-readable log
  3. Analysis engine   - daily totals + mean / standard deviation from a log
  4. Alert engine      - compare "live" days against the baseline, flag anomalies
"""
import math
import os
import random
import sys

OUT_DIR = "output"
BASELINE_LOG = os.path.join(OUT_DIR, "baseline_log.txt")
BASELINE_TOTALS = os.path.join(OUT_DIR, "baseline_daily_totals.txt")
BASELINE_STATS = os.path.join(OUT_DIR, "baseline_stats.txt")


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------
class EventDef:
    """One line of Events.txt."""

    def __init__(self, name, kind, minimum, maximum, weight):
        self.name = name
        self.kind = kind            # 'C' or 'D'
        self.minimum = minimum      # float/int or None (no lower bound)
        self.maximum = maximum      # float/int or None (no upper bound)
        self.weight = weight        # positive int

    @property
    def discrete(self):
        return self.kind == "D"


class Stat:
    """One line of Stats.txt."""

    def __init__(self, name, mean, sd):
        self.name = name
        self.mean = mean
        self.sd = sd


class InputError(Exception):
    pass


# --------------------------------------------------------------------------
# 1. Initial input: parsing + consistency checks
# --------------------------------------------------------------------------
def _read_lines(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            lines = [ln.strip() for ln in f.read().splitlines()]
    except OSError as e:
        raise InputError("Cannot read '%s': %s" % (path, e))
    while lines and lines[-1] == "":
        lines.pop()
    if not lines:
        raise InputError("'%s' is empty" % path)
    return lines


def _num(text):
    try:
        return float(text)
    except ValueError:
        return None


def load_events(path):
    """Returns (list[EventDef], issues). issues = list of (level, message)."""
    lines = _read_lines(path)
    issues = []
    if not lines[0].isdigit():
        raise InputError("%s line 1: expected number of events, got '%s'" % (path, lines[0]))
    declared = int(lines[0])
    body = [ln for ln in lines[1:] if ln != ""]
    if declared != len(body):
        issues.append(("ERROR", "%s: header says %d events but %d event lines found"
                       % (path, declared, len(body))))
    events, seen = [], set()
    for i, ln in enumerate(body, start=2):
        p = ln.split(":")
        if len(p) < 5:
            issues.append(("ERROR", "%s line %d: expected 'name:C|D:min:max:weight:'" % (path, i)))
            continue
        name, kind, smin, smax, sw = [x.strip() for x in p[:5]]
        if name == "":
            issues.append(("ERROR", "%s line %d: empty event name" % (path, i)))
            continue
        if name.lower() in seen:
            issues.append(("ERROR", "%s line %d: duplicate event name '%s'" % (path, i, name)))
            continue
        seen.add(name.lower())
        kind = kind.upper()
        if kind not in ("C", "D"):
            issues.append(("ERROR", "%s line %d: type must be C or D, got '%s'" % (path, i, kind)))
            continue
        mn = mx = None
        ok = True
        if smin != "":
            mn = _num(smin)
            if mn is None:
                issues.append(("ERROR", "%s line %d: minimum '%s' is not a number" % (path, i, smin)))
                ok = False
        if smax != "":
            mx = _num(smax)
            if mx is None:
                issues.append(("ERROR", "%s line %d: maximum '%s' is not a number" % (path, i, smax)))
                ok = False
        if not ok:
            continue
        if kind == "D":
            for label, v in (("minimum", mn), ("maximum", mx)):
                if v is not None and v != int(v):
                    issues.append(("ERROR", "%s line %d: discrete event '%s' has non-integer %s %s"
                                   % (path, i, name, label, v)))
                    ok = False
            if mn is not None:
                mn = int(mn)
            if mx is not None:
                mx = int(mx)
        if not ok:
            continue
        if mn is not None and mx is not None and mn > mx:
            issues.append(("ERROR", "%s line %d: '%s' minimum %s > maximum %s" % (path, i, name, mn, mx)))
            continue
        if not sw.isdigit() or int(sw) <= 0:
            issues.append(("ERROR", "%s line %d: weight '%s' must be a positive integer" % (path, i, sw)))
            continue
        events.append(EventDef(name, kind, mn, mx, int(sw)))
    return events, issues


def load_stats(path):
    """Returns (list[Stat], issues)."""
    lines = _read_lines(path)
    issues = []
    if not lines[0].isdigit():
        raise InputError("%s line 1: expected number of events, got '%s'" % (path, lines[0]))
    declared = int(lines[0])
    body = [ln for ln in lines[1:] if ln != ""]
    if declared != len(body):
        issues.append(("ERROR", "%s: header says %d events but %d stat lines found"
                       % (path, declared, len(body))))
    stats, seen = [], set()
    for i, ln in enumerate(body, start=2):
        p = ln.split(":")
        if len(p) < 3:
            issues.append(("ERROR", "%s line %d: expected 'name:mean:sd:'" % (path, i)))
            continue
        name, smean, ssd = [x.strip() for x in p[:3]]
        mean, sd = _num(smean), _num(ssd)
        if mean is None or sd is None:
            issues.append(("ERROR", "%s line %d: mean/sd not numeric ('%s','%s')" % (path, i, smean, ssd)))
            continue
        if sd < 0:
            issues.append(("ERROR", "%s line %d: negative standard deviation for '%s'" % (path, i, name)))
            continue
        if name.lower() in seen:
            issues.append(("ERROR", "%s line %d: duplicate stat name '%s'" % (path, i, name)))
            continue
        seen.add(name.lower())
        stats.append(Stat(name, mean, sd))
    return stats, issues


def _phi(z):
    return 0.5 * (1.0 + math.erf(z / math.sqrt(2.0)))


def cross_check(events, stats, stats_path="Stats.txt"):
    """Detect inconsistencies between the event definitions and a stats file.
    Returns (issues, ordered_stats) where ordered_stats is aligned with events
    (None for a missing entry)."""
    issues = []
    ev_by = {e.name.lower(): e for e in events}
    st_by = {s.name.lower(): s for s in stats}
    if len(events) != len(stats):
        issues.append(("ERROR", "event count differs: %d events vs %d stats" % (len(events), len(stats))))
    for e in events:
        if e.name.lower() not in st_by:
            issues.append(("ERROR", "event '%s' has no entry in %s" % (e.name, stats_path)))
    for s in stats:
        if s.name.lower() not in ev_by:
            issues.append(("ERROR", "%s entry '%s' is not defined in Events.txt (spelling?)"
                           % (stats_path, s.name)))
    for e in events:
        s = st_by.get(e.name.lower())
        if s is None:
            continue
        if s.name != e.name:
            issues.append(("WARN", "name differs only by case: '%s' vs '%s'" % (e.name, s.name)))
        lo, hi = e.minimum, e.maximum
        if lo is not None and s.mean < lo:
            issues.append(("ERROR", "'%s': mean %.2f is below minimum %s" % (e.name, s.mean, lo)))
        if hi is not None and s.mean > hi:
            issues.append(("ERROR", "'%s': mean %.2f is above maximum %s" % (e.name, s.mean, hi)))
        if s.sd == 0:
            issues.append(("WARN", "'%s': standard deviation is 0 (every day identical; "
                                   "anomaly scores for this event become degenerate)" % e.name))
        elif (lo is None or lo <= s.mean) and (hi is None or s.mean <= hi):
            # how much of the requested normal curve falls outside the allowed range?
            pad = 0.5 if e.discrete else 0.0
            p_out = 0.0
            if lo is not None:
                p_out += _phi((lo - pad - s.mean) / s.sd)
            if hi is not None:
                p_out += 1.0 - _phi((hi + pad - s.mean) / s.sd)
            if p_out > 0.05:
                issues.append(("WARN", "'%s': %.1f%% of N(%.2f, %.2f) lies outside [%s, %s]; generated "
                                       "data cannot match the requested statistics"
                               % (e.name, 100 * p_out, s.mean, s.sd,
                                  "-inf" if lo is None else lo, "+inf" if hi is None else hi)))
        if e.discrete and s.sd > 0 and s.mean < 0:
            issues.append(("ERROR", "'%s': negative mean for a count event" % e.name))
    if [e.name.lower() for e in events] != [s.name.lower() for s in stats] \
            and len(events) == len(stats) and set(ev_by) == set(st_by):
        issues.append(("WARN", "events appear in a different order in the two files "
                               "(matched by name, so this is harmless)"))
    ordered = [st_by.get(e.name.lower()) for e in events]
    return issues, ordered


def print_issues(issues):
    if not issues:
        print("  No inconsistencies detected.")
    for level, msg in issues:
        print("  [%s] %s" % (level, msg))
    return any(l == "ERROR" for l, _ in issues)


def print_model(events, ordered_stats):
    print("  %-16s %-4s %8s %8s %6s %10s %10s" %
          ("Event", "Type", "Min", "Max", "Weight", "Mean", "StdDev"))
    for e, s in zip(events, ordered_stats):
        mn = "-" if e.minimum is None else "%g" % e.minimum
        mx = "-" if e.maximum is None else "%g" % e.maximum
        print("  %-16s %-4s %8s %8s %6d %10.2f %10.2f" %
              (e.name, e.kind, mn, mx, e.weight, s.mean, s.sd))


# --------------------------------------------------------------------------
# 2. Activity engine
# --------------------------------------------------------------------------
def _in_range(ev, v):
    if ev.minimum is not None and v < ev.minimum:
        return False
    if ev.maximum is not None and v > ev.maximum:
        return False
    return True


def _clamp(ev, v):
    if ev.minimum is not None and v < ev.minimum:
        v = ev.minimum
    if ev.maximum is not None and v > ev.maximum:
        v = ev.maximum
    return v


def sample_daily_total(ev, st, rng):
    """Draw one day's total for an event from N(mean, sd), truncated to the
    allowed range by rejection sampling (falls back to clamping)."""
    v = None
    for _ in range(1000):
        x = rng.gauss(st.mean, st.sd)
        v = int(round(x)) if ev.discrete else round(x, 2)
        if _in_range(ev, v):
            return v
    return _clamp(ev, v)


def _is_login(ev):
    return ev.name.strip().lower() in ("logins", "login")


def generate_day_totals(events, stats, rng):
    totals = []
    for e, s in zip(events, stats):
        v = sample_daily_total(e, s, rng)
        if _is_login(e) and v < 1:
            # A day with no login would force every other event to 0 and distort
            # their distributions, so redraw (only gives up if logins are ~always 0).
            for _ in range(100):
                v = sample_daily_total(e, s, rng)
                if v >= 1:
                    break
        totals.append(v)
    # Consistency rule: nothing can happen on a day with no login
    login_idx = next((i for i, e in enumerate(events) if _is_login(e)), None)
    if login_idx is not None and totals[login_idx] == 0:
        for i, e in enumerate(events):
            if i != login_idx and (e.minimum is None or e.minimum <= 0):
                totals[i] = 0 if e.discrete else 0.0
    return totals, login_idx


def split_cents(total, k, rng):
    """Split a 2dp amount into k non-negative 2dp pieces that sum exactly."""
    cents = int(round(total * 100))
    cuts = sorted(rng.randint(0, cents) for _ in range(k - 1))
    pts = [0] + cuts + [cents]
    return [(pts[i + 1] - pts[i]) / 100.0 for i in range(k)]


def fmt_hms(sec):
    return "%02d:%02d:%02d" % (sec // 3600, (sec % 3600) // 60, sec % 60)


def run_activity_engine(events, stats, days, log_path, rng, label="baseline"):
    """Generate `days` days of activity and write them to log_path.
    Log line: Day|HH:MM:SS|Event|Value  (lines starting with # are comments)."""
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    print("[Activity engine] Generating %d day(s) of %s activity ..." % (days, label))
    step = max(1, days // 10)
    with open(log_path, "w", encoding="utf-8") as f:
        f.write("# CSCI262 A3 activity log\n")
        f.write("# days=%d\n" % days)
        f.write("# format: Day|HH:MM:SS|Event|Value\n")
        for d in range(1, days + 1):
            totals, login_idx = generate_day_totals(events, stats, rng)
            rows = []
            for i, (e, t) in enumerate(zip(events, totals)):
                if t == 0:
                    continue
                if e.discrete:
                    for _ in range(int(t)):
                        rows.append((rng.randint(0, 86399), e.name, "1"))
                else:
                    n_login = totals[login_idx] if login_idx is not None else 0
                    k = int(n_login) if n_login and n_login > 0 else rng.randint(1, 3)
                    k = max(1, min(k, int(round(t * 100))))
                    for piece in split_cents(t, k, rng):
                        if piece > 0:
                            rows.append((rng.randint(0, 86399), e.name, "%.2f" % piece))
            rows.sort(key=lambda r: r[0])
            for sec, name, val in rows:
                f.write("%04d|%s|%s|%s\n" % (d, fmt_hms(sec), name, val))
            if d % step == 0 or d == days:
                print("  ... day %d / %d" % (d, days))
    print("[Activity engine] Done. Log written to %s" % log_path)


# --------------------------------------------------------------------------
# 3. Analysis engine
# --------------------------------------------------------------------------
def read_log(log_path, events):
    """Returns (days, totals) where totals[d-1][event_index] is the day's total."""
    idx = {e.name.lower(): i for i, e in enumerate(events)}
    days = 0
    rows = []
    with open(log_path, "r", encoding="utf-8") as f:
        for n, ln in enumerate(f, 1):
            ln = ln.strip()
            if not ln:
                continue
            if ln.startswith("#"):
                if ln.startswith("# days="):
                    days = int(ln.split("=", 1)[1])
                continue
            p = ln.split("|")
            if len(p) != 4 or p[2].lower() not in idx:
                print("  [warning] skipping malformed log line %d: %s" % (n, ln))
                continue
            try:
                rows.append((int(p[0]), idx[p[2].lower()], float(p[3])))
            except ValueError:
                print("  [warning] skipping malformed log line %d: %s" % (n, ln))
    days = max([days] + [r[0] for r in rows])
    totals = [[0.0] * len(events) for _ in range(days)]
    for d, i, v in rows:
        totals[d - 1][i] += v
    for d in range(days):
        for i, e in enumerate(events):
            totals[d][i] = int(round(totals[d][i])) if e.discrete else round(totals[d][i], 2)
    return days, totals


def mean_sd(values):
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = sum(values) / n
    var = sum((v - m) ** 2 for v in values) / n      # population standard deviation
    return m, math.sqrt(var)


def write_totals(path, events, totals):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Day:" + ":".join(e.name for e in events) + ":\n")
        for d, row in enumerate(totals, 1):
            f.write("%d:" % d + ":".join(("%d" % v) if e.discrete else ("%.2f" % v)
                                          for e, v in zip(events, row)) + ":\n")


def write_stats(path, events, stats):
    with open(path, "w", encoding="utf-8") as f:
        f.write("%d\n" % len(events))
        for e, s in zip(events, stats):
            f.write("%s:%.4f:%.4f:\n" % (e.name, s.mean, s.sd))


def run_analysis_engine(events, log_path, totals_path, stats_path=None, label="baseline"):
    print("[Analysis engine] Reading %s log %s ..." % (label, log_path))
    days, totals = read_log(log_path, events)
    print("[Analysis engine] Computing daily totals for %d day(s) ..." % days)
    write_totals(totals_path, events, totals)
    print("[Analysis engine] Daily totals saved to %s" % totals_path)
    stats = []
    for i, e in enumerate(events):
        m, sd = mean_sd([row[i] for row in totals])
        stats.append(Stat(e.name, m, sd))
    if stats_path:
        write_stats(stats_path, events, stats)
        print("[Analysis engine] Mean / std-dev saved to %s" % stats_path)
    return totals, stats


# --------------------------------------------------------------------------
# 4. Alert engine
# --------------------------------------------------------------------------
def deviation(value, mean, sd):
    """Absolute number of standard deviations between value and mean."""
    if sd > 0:
        return abs(value - mean) / sd
    return 0.0 if value == mean else abs(value - mean)   # sd = 0: treat 1 unit as 1 sd


def anomaly_counter(events, baseline, row):
    return sum(e.weight * deviation(v, b.mean, b.sd) for e, b, v in zip(events, baseline, row))


def report_alerts(events, baseline, totals):
    threshold = 2 * sum(e.weight for e in events)
    print("\n  %-5s %-10s %-10s %-8s" % ("Day", "Counter", "Threshold", "Status"))
    flagged = 0
    for d, row in enumerate(totals, 1):
        c = anomaly_counter(events, baseline, row)
        status = "FLAGGED" if c >= threshold else "okay"
        flagged += status == "FLAGGED"
        print("  %-5d %-10.2f %-10d %-8s" % (d, c, threshold, status))
    print("  -> %d of %d day(s) flagged (threshold = 2 x sum of weights = %d)"
          % (flagged, len(totals), threshold))


def prompt(msg):
    try:
        return input(msg).strip()
    except EOFError:
        return "q"


def alert_loop(events, baseline, rng):
    run = 0
    while True:
        print("\n=== Alert engine ===")
        path = prompt("Enter new statistics file (or 'q' to quit): ")
        if path.lower() in ("q", "quit"):
            print("Goodbye.")
            return
        try:
            new_stats, issues = load_stats(path)
        except InputError as e:
            print("  Error:", e)
            continue
        c_issues, ordered = cross_check(events, new_stats, path)
        print("Checking %s against Events.txt:" % path)
        if print_issues(issues + c_issues):
            print("  Fix the errors above and try again.")
            continue
        ds = prompt("Number of days to simulate: ")
        if not ds.isdigit() or int(ds) < 1:
            print("  Error: days must be a positive integer.")
            continue
        days = int(ds)
        run += 1
        log_path = os.path.join(OUT_DIR, "live_log_%d.txt" % run)
        tot_path = os.path.join(OUT_DIR, "live_daily_totals_%d.txt" % run)
        run_activity_engine(events, ordered, days, log_path, rng, label="live")
        totals, _ = run_analysis_engine(events, log_path, tot_path, None, label="live")
        print("[Alert engine] Comparing each day to the baseline ...")
        report_alerts(events, baseline, totals)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main(argv):
    seed = None
    if "--seed" in argv:
        i = argv.index("--seed")
        seed = int(argv[i + 1])
        del argv[i:i + 2]
    if len(argv) != 4:
        print("Usage: python IDS.py Events.txt Stats.txt Days [--seed N]")
        return 2
    events_path, stats_path, days_s = argv[1], argv[2], argv[3]
    if not days_s.isdigit() or int(days_s) < 1:
        print("Error: Days must be a positive integer.")
        return 2
    days = int(days_s)
    rng = random.Random(seed)

    print("=== Initial input ===")
    try:
        events, ev_issues = load_events(events_path)
        stats, st_issues = load_stats(stats_path)
    except InputError as e:
        print("Error:", e)
        return 1
    c_issues, ordered = cross_check(events, stats, stats_path)
    print("Read %d event definition(s) from %s and %d statistic(s) from %s."
          % (len(events), events_path, len(stats), stats_path))
    print("Consistency check:")
    if print_issues(ev_issues + st_issues + c_issues):
        print("Errors found - cannot continue.")
        return 1
    print_model(events, ordered)

    print("\n=== Activity engine ===")
    run_activity_engine(events, ordered, days, BASELINE_LOG, rng)
    print("Event generation complete.\n")

    print("=== Analysis engine ===")
    print("Starting analysis phase.")
    _, baseline = run_analysis_engine(events, BASELINE_LOG, BASELINE_TOTALS, BASELINE_STATS)
    print("\n  Baseline statistics measured from the generated log:")
    print("  %-16s %10s %10s   (requested: %8s %8s)" % ("Event", "Mean", "StdDev", "Mean", "StdDev"))
    for e, b, s in zip(events, baseline, ordered):
        print("  %-16s %10.2f %10.2f   (           %8.2f %8.2f)" % (e.name, b.mean, b.sd, s.mean, s.sd))

    alert_loop(events, baseline, rng)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))