from tests.pycryptodome import dome_lib
from utils.path import path


def main(large_size_mb=50):
    """Run the AES benchmark suite for all configured modes."""
    key = dome_lib.get_key(path("files/key.bin"), 32)
    results = dome_lib.run_benchmarks(
        path("files/benchmarks"),
        key,
        large_size_mb=large_size_mb,
    )
    print(dome_lib.format_benchmark_results(results))

    return results

