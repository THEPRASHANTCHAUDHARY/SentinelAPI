from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "public"

def main() -> None:
    """Mirror the existing root-level pages and assets into Vercel's public/ tree."""
    PUBLIC.mkdir(parents=True, exist_ok=True)
    for page in ROOT.glob("*.html"):
        shutil.copy2(page, PUBLIC / page.name)
    shutil.copytree(ROOT / "assets", PUBLIC / "assets", dirs_exist_ok=True)

if __name__ == "__main__":
    main()
