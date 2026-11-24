"""Atomic publication primitives shared by generated output and saved YAML."""

from __future__ import annotations

import os
from pathlib import Path


def publish_file(temporary_path: Path, final_path: Path, *, overwrite: bool) -> None:
    """Publish a complete same-filesystem temp file.

    ``os.link`` is the portable no-clobber primitive: creation of the final
    directory entry is atomic and fails if another process won the race. The
    temporary file lives beside the destination, so both paths share a volume.
    """

    if overwrite:
        os.replace(temporary_path, final_path)
        return
    try:
        os.link(temporary_path, final_path, follow_symlinks=False)
    except FileExistsError:
        raise
    except OSError:
        if os.name != "nt":
            raise
        # Windows rename is no-clobber (unlike POSIX rename), so it is a safe
        # fallback for FAT/exFAT/SMB volumes that do not implement hard links.
        os.rename(temporary_path, final_path)
        return
    try:
        temporary_path.unlink()
    except OSError:
        # The published file is already complete and valid. A stale .part is
        # preferable to reporting a failed generation after successful commit.
        pass
