from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
from tests.nist_test.test_vectors import NIST_PLAINTEXT


BENCHMARK_SAMPLE_NAMES = (
  "sample_text.txt",
  "structured_payload.json",
  "binary_pattern.bin",
)


def _sample(name, data, sample_type, source):
  return {
    "name": name,
    "data": data,
    "type": sample_type,
    "source": source,
  }


def get_inline_file_samples():
  return [
    _sample(
      "inline_note.txt",
      (
        b"AES test sample.\n"
        b"Deterministic text payload for NIST-oriented validation.\n"
        b"Line 3 keeps the content unaligned."
      ),
      "txt",
      "inline",
    ),
    _sample(
      "inline_config.json",
      (
        b'{'
        b'"name":"nist-suite",'
        b'"version":1,'
        b'"flags":["ecb","cbc","ctr"],'
        b'"deterministic":true'
        b'}'
      ),
      "json",
      "inline",
    ),
    _sample(
      "inline_binary.bin",
      bytes(range(32)) + b"\x00\xff\x10\x20\x30\x40\x50",
      "binary",
      "inline",
    ),
    _sample(
      "inline_exact_block.bin",
      bytes.fromhex("00112233445566778899aabbccddeeff"),
      "binary",
      "inline",
    ),
  ]


def load_project_file_samples():
  benchmark_dir = (PROJECT_ROOT / "files" / "benchmarks").resolve()
  samples = []

  for file_name in BENCHMARK_SAMPLE_NAMES:
    file_path = benchmark_dir / file_name
    if not file_path.exists() or not file_path.is_file():
      continue

    samples.append(
      _sample(
        file_name,
        file_path.read_bytes(),
        file_path.suffix.lower().lstrip(".") or "binary",
        "project",
      )
    )

  return samples


def load_file_samples():
  return get_inline_file_samples() + load_project_file_samples()


def build_mmt_samples():
  samples = []

  for block_count in range(1, 11):
    data = (NIST_PLAINTEXT * block_count)[:16 * block_count]
    samples.append(
      _sample(
        f"mmt_{block_count:02d}_blocks.bin",
        data,
        "binary",
        "generated",
      )
    )

  return samples


# --- Manual Test ---
# from tests.nist_test.file_samples import load_file_samples, build_mmt_samples
# print(len(load_file_samples()), len(build_mmt_samples()))
