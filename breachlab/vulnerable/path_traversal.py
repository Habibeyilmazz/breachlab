"""Challenge: path traversal in the export download.

Stage 2: patch export_path, then run `pytest fix_tests -k path_traversal`.
"""

from pathlib import Path


# BREACHLAB: patch this function
def export_path(exports_dir: Path, file_name: str):
    """Return the path of the export file to send, or None when there is nothing to send."""
    return exports_dir / file_name
