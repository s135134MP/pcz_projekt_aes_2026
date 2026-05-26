def _format_key_size(value):
  return f"AES-{value}" if value else "N/A"


def _format_duration(value):
  return f"{value * 1000:.3f} ms"


def _format_memory(value):
  if value >= 1024 * 1024:
    return f"{value / (1024 * 1024):.2f} MiB"
  if value >= 1024:
    return f"{value / 1024:.2f} KiB"
  return f"{value} B"


def _format_throughput(value):
  if value <= 0:
    return "n/a"
  return f"{value:.3f} MiB/s"


def _render_table(columns, rows):
  widths = []

  for key, header, formatter in columns:
    width = len(header)
    for row in rows:
      width = max(width, len(formatter(row.get(key))))
    widths.append(width)

  header = " | ".join(header.ljust(widths[index]) for index, (_, header, _) in enumerate(columns))
  separator = "-+-".join("-" * width for width in widths)
  lines = [header, separator]

  for row in rows:
    lines.append(
      " | ".join(
        formatter(row.get(key)).ljust(widths[index])
        for index, (key, _, formatter) in enumerate(columns)
      )
    )

  return "\n".join(lines)


def print_test_result(result):
  print(
    f"[{result['status']}] "
    f"{_format_key_size(result['key_size'])} {result['mode']} {result['operation']} | "
    f"{result['sample_name']} | "
    f"{_format_duration(result['duration'])} | "
    f"memory: {_format_memory(result['peak_bytes'])} | "
    f"validation: {result['validation_result']}"
  )


def _build_summary_rows(results, key_builder):
  groups = {}

  for result in results:
    group_name = key_builder(result)
    groups.setdefault(group_name, []).append(result)

  rows = []

  for group_name in sorted(groups):
    group_results = groups[group_name]
    passed_results = [item for item in group_results if item["status"] == "PASS"]

    rows.append({
      "group": group_name,
      "passed": f"{len(passed_results)}/{len(group_results)}",
      "avg_duration": (
        sum(item["duration"] for item in passed_results) / len(passed_results)
        if passed_results else 0.0
      ),
      "avg_memory": (
        sum(item["peak_bytes"] for item in passed_results) / len(passed_results)
        if passed_results else 0.0
      ),
      "avg_throughput": (
        sum(item["throughput_mib_s"] for item in passed_results) / len(passed_results)
        if passed_results else 0.0
      ),
    })

  return rows


def print_summary(results):
  summary_columns = [
    ("group", "Group", str),
    ("passed", "Passed", str),
    ("avg_duration", "Avg Time", _format_duration),
    ("avg_memory", "Avg Memory", _format_memory),
    ("avg_throughput", "Avg Throughput", _format_throughput),
  ]
  failure_columns = [
    ("mode", "Mode", str),
    ("key_size", "Key", _format_key_size),
    ("operation", "Operation", str),
    ("sample_name", "Sample", str),
    ("category", "Category", str),
    ("note", "Notes", str),
  ]

  print()
  print("Summary by mode and operation")
  print(_render_table(summary_columns, _build_summary_rows(results, lambda item: item["mode"] + " / " + item["operation"])))
  print()
  print("Summary by key size")
  print(_render_table(summary_columns, _build_summary_rows(results, lambda item: _format_key_size(item["key_size"]))))
  print()
  print("Summary by category")
  print(_render_table(summary_columns, _build_summary_rows(results, lambda item: item["category"])))

  failed_results = [item for item in results if item["status"] != "PASS"]
  if failed_results:
    print()
    print("Failures")
    print(_render_table(failure_columns, failed_results))


def print_final_summary(results):
  passed_results = [item for item in results if item["status"] == "PASS"]
  failed_results = [item for item in results if item["status"] != "PASS"]

  print()
  print("Final summary")
  print("Executed tests:", len(results))
  print("Passed:", len(passed_results))
  print("Failed:", len(failed_results))


# --- Manual Test ---
# print_test_result({"status":"PASS","key_size":128,"mode":"ECB","operation":"Encryption","sample_name":"sample.bin","duration":0.001,"peak_bytes":1024,"validation_result":"PASS"})
