# Configuration

Everything configurable lives in the `config/` folder. Changes take effect
the next time the auditor is started (the sensitive-file watchlist is also
re-read while it runs).

A missing or malformed file never stops the auditor: it prints a
`[config] WARNING` line and uses the safe default shown below.

## `config/settings.json`

| Setting | Default | Used by | Meaning |
|---|---|---|---|
| `polling_interval_seconds` | `2` | Process Watcher | Seconds between polls. Minimum 0.5. Can be overridden with `--interval`. |
| `alert_cooldown_seconds` | `120` | Alert De-duplication | The same finding (process + rule + object) is not reported again until it has been absent this long. `0` disables de-duplication. |
| `correlation_window_seconds` | `60` | Event Correlation | How long a process's earlier findings are remembered and added to a new alert for the same process. |
| `process_burst_threshold` | `10` | Process Creation Burst | Number of children that makes a burst. Minimum 2. |
| `process_burst_window_seconds` | `10` | Process Creation Burst | Time window in which those children must have been created. |
| `process_burst_ignored_parents` | `["launchd", "kernel_task"]` | Process Creation Burst | Parent names that are never reported (they start everything). |
| `resource_cpu_threshold_percent` | `90` | Resource Usage Anomaly | CPU threshold. 100 = one full CPU core, so multi-threaded processes can exceed 100. |
| `resource_memory_threshold_percent` | `80` | Resource Usage Anomaly | Memory threshold, as a share of physical RAM. |
| `resource_sustained_cycles` | `5` | Resource Usage Anomaly | Consecutive polls above a threshold before an alert is raised (5 polls × 2 s = 10 s). |
| `auto_response_action` | `"suspend"` | Auto-Response | `"suspend"` (reversible) or `"terminate"` for Critical alerts. |
| `auto_response_scope` | `"test_only"` | Auto-Response | `"test_only"`: only controlled test processes may be acted on. `"all_unprotected"`: any process that is not protected. |
| `log_dir` | `"logs"` | Logging | Folder for `audit.log`, `alerts.jsonl`, `auditor_state.json`. |
| `dashboard_host` | `"127.0.0.1"` | Dashboard | Address the dashboard listens on. Keep it local. |
| `dashboard_port` | `5050` | Dashboard | Port (macOS uses 5000 for AirPlay Receiver). |

Choosing thresholds:

- A **shorter polling interval** detects faster and misses less, but uses more CPU.
- A **lower burst threshold** or a **longer window** catches smaller bursts but
  reports ordinary scripts and builds more often.
- **Fewer sustained cycles** reports CPU spikes sooner but more noisily.

## `config/sensitive_files.txt` - watchlist

One path per line; `#` starts a comment.

```
~/.ssh/id_rsa                      # ~ expands to the home directory
/etc/sudoers                       # absolute path
tests/sandbox/sensitive/x.txt      # relative paths start at the project root
~/Documents/secret/                # trailing / watches every file inside
tests/sandbox/sensitive/notes.txt | low    # optional tag: low sensitivity -> LOW alert
```

The auditor never opens these files; it compares the paths of files that
processes already have open.

## `config/parent_rules.json` - unusual parent-child rules

```json
{
  "rules": [
    {
      "name": "browser-spawns-shell",
      "description": "A web browser started a command shell",
      "parents": ["safari*", "google chrome*", "firefox*"],
      "children": ["sh", "bash", "zsh"]
    }
  ]
}
```

A process is flagged when its parent's name matches one of `parents` **and**
its own name matches one of `children`. Matching is case-insensitive and `*`
is a wildcard. A rule that is missing `parents` or `children` is skipped.

## `config/suspicious_locations.txt` - suspicious execution locations

One **directory** per line; `~` and project-relative paths work. A process is
flagged when its executable file is inside one of these directories or their
sub-directories.

Defaults: `/tmp`, `/var/tmp`, `/Users/Shared`, `~/Downloads`, `~/.Trash`, and
the test location `tests/sandbox/unusual_location`. An entry of `/` is
ignored, because it would match every process.

## `config/protected_processes.json` - protected process list

| Key | Meaning |
|---|---|
| `protected_names` | Process names that automatic response must never act on (case-insensitive). |
| `protected_pids` | PIDs that are always protected. 0 and 1 are added automatically. |
| `test_policy_protected_names` | Names protected for testing; contains the Scenario F fixture `psa_protected_fixture`. |

The auditor itself and its parent processes (your shell and terminal) are
always protected, whatever this file says. If the file is missing or has no
names, a built-in list of core macOS processes is used, so the protected list
can never become empty by accident.

## Command-line options

```
python3 -m src.main [--interval SECONDS] [--test-mode] [--cycles N] [--quiet]
python3 -m src.dashboard [--port PORT] [--host HOST]
python3 -m tests.scenario_x [--hold SECONDS] [--json FILE]
```

`--test-mode` enables the controlled test injection used by scenarios C, E
and F (see [testing.md](testing.md)). It changes nothing else.
