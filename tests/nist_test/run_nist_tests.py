import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
  sys.path.insert(0, str(PROJECT_ROOT))

from tests.nist_test import cbc_tests, ctr_tests, ecb_tests
from tests.nist_test.console_report import print_summary, print_test_result


MODE_RUNNERS = {
  "ECB": ecb_tests.run_tests,
  "CBC": cbc_tests.run_tests,
  "CTR": ctr_tests.run_tests,
}


def run_all_tests(selected_modes=None):
  modes = selected_modes or tuple(MODE_RUNNERS.keys())
  results = []

  for mode in modes:
    runner = MODE_RUNNERS[mode]
    mode_results = runner()

    for result in mode_results:
      print_test_result(result)

    results.extend(mode_results)

  print_summary(results)
  return results


def main():
  parser = argparse.ArgumentParser(description="Run the NIST-oriented AES test suite.")
  parser.add_argument(
    "--mode",
    action="append",
    choices=sorted(MODE_RUNNERS.keys()),
    help="Run only the selected AES mode. Repeat to select multiple modes.",
  )
  args = parser.parse_args()

  return run_all_tests(args.mode)


if __name__ == "__main__":
  main()


# --- Manual Test ---
# python tests/nist_test/run_nist_tests.py
# python tests/nist_test/run_nist_tests.py --mode ECB --mode CTR
