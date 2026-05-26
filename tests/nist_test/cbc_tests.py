from tests.nist_test.file_samples import build_mmt_samples, load_file_samples
from tests.nist_test.test_vectors import NIST_VECTORS
from tests.nist_test.utils import run_file_sample_tests, run_mmt_tests, run_validation_tests, run_vector_tests


def run_tests():
  results = []
  results.extend(run_vector_tests("CBC", NIST_VECTORS["CBC"]))
  results.extend(run_mmt_tests("CBC", build_mmt_samples()))
  results.extend(run_file_sample_tests("CBC", load_file_samples()))
  results.extend(run_validation_tests("CBC"))
  return results


# --- Manual Test ---
# from tests.nist_test.cbc_tests import run_tests
# print(len(run_tests()))
