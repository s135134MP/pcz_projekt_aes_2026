import time
import tracemalloc


def measure_operation(callable_object, *args, **kwargs):
  tracemalloc.start()
  start_time = time.perf_counter()

  try:
    result = callable_object(*args, **kwargs)
    error = ""
    error_type = ""
  except Exception as exc:
    result = None
    error = str(exc)
    error_type = type(exc).__name__

  end_time = time.perf_counter()
  _, peak_bytes = tracemalloc.get_traced_memory()
  tracemalloc.stop()

  return {
    "result": result,
    "error": error,
    "error_type": error_type,
    "duration": end_time - start_time,
    "peak_bytes": peak_bytes,
  }


# --- Manual Test ---
# from tests.nist_test.performance_metrics import measure_operation
# print(measure_operation(lambda: b"ok"))
