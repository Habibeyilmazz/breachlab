"""Reference fix: path traversal.

Why the hole existed
    The file name from the request was joined onto the exports folder. `..`
    segments walk back out of that folder, and an absolute path replaces the folder
    entirely (Path("/a") / "/etc/passwd" is "/etc/passwd").

Why this fix works
    The joined path is resolved first, which removes `..` and follows symlinks,
    giving the real location on disk. Only then do we ask whether that location is
    still inside the exports folder. Checking the raw string for ".." instead is
    fragile; checking the resolved path cannot be fooled by encoding tricks.

The secure pattern
    Best: do not accept file names at all. Accept an id, look the file up in your
    own records. If a name must come from the user: resolve, then verify
    containment with is_relative_to (not startswith, which lets "exports-old"
    pass for "exports"). Keep downloadable files in a folder that holds nothing else.
"""

from pathlib import Path


def export_path(exports_dir: Path, file_name: str):
    """Return the path of the export file to send, or None when there is nothing to send."""
    base = exports_dir.resolve()
    try:
        candidate = (base / file_name).resolve()
    except (OSError, ValueError):  # e.g. a NUL byte in the name
        return None
    return candidate if candidate.is_relative_to(base) and candidate.is_file() else None
