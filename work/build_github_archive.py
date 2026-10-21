"""Create a deterministic source-only GitHub upload archive."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


def build(root: Path) -> Path:
    root = Path(root).resolve()
    source = root / "github" / "CastorPollux"
    target = root / "outputs" / "CastorPollux-GitHub-Source.zip"
    with ZipFile(target, "w", compression=ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file() or any(part in {".git", "__pycache__"} for part in path.parts):
                continue
            entry = ZipInfo(path.relative_to(source).as_posix(), date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, path.read_bytes(), compress_type=ZIP_DEFLATED, compresslevel=6)
    return target


if __name__ == "__main__":
    print(build(Path(__file__).resolve().parent.parent))
