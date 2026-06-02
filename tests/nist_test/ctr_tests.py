from tests.nist_test.file_samples import build_mmt_samples, load_file_samples
from tests.nist_test.test_vectors import NIST_VECTORS
from tests.nist_test.utils import run_file_sample_tests, run_mmt_tests, run_validation_tests, run_vector_tests


def run_tests():
  results = []
  results.extend(run_vector_tests("CTR", NIST_VECTORS["CTR"]))
  results.extend(run_mmt_tests("CTR", build_mmt_samples()))
  results.extend(run_file_sample_tests("CTR", load_file_samples()))
  results.extend(run_validation_tests("CTR"))
  return results


# --- Manual Test ---
# from tests.nist_test.ctr_tests import run_tests
# print(len(run_tests()))
