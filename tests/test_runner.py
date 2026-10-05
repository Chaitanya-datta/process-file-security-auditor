"""Runs all test scenarios (A-J) and writes the results table.

    python3 -m tests.test_runner

A-F are the six original scenarios; G, H and I cover the three added
detections; J covers event correlation and de-duplication.

If an auditor is already running in --test-mode it is used (so the alerts also
appear on the dashboard). Otherwise a temporary auditor is started and stopped
automatically. Results are saved in results/test_results.md, .csv and .json.
"""

import sys

from tests import (scenario_a, scenario_b, scenario_c, scenario_d, scenario_e, scenario_f,
                   scenario_g, scenario_h, scenario_i, scenario_j)
from tests.harness import run_scenarios

SCENARIOS = [scenario_a.run, scenario_b.run, scenario_c.run,
             scenario_d.run, scenario_e.run, scenario_f.run, scenario_g.run,
             scenario_h.run, scenario_i.run, scenario_j.run]

if __name__ == "__main__":
    sys.exit(run_scenarios(SCENARIOS, save=True))
