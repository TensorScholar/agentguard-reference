import hashlib
import re
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP_LEVEL = (".gitignore", "README.md", "CHANGELOG.md", "SECURITY.md", "LICENSE",
             "Makefile", "pyproject.toml")
DIRECTORIES = {"src": {".py"}, "tests": {".py"}, "examples": {".py", ".md"},
               "docs": {".md"}, "scripts": {".py"}}
FORBIDDEN = (
    b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----", b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----", b"/Users/", b"/home/", b"C:\\Users\\",
    b"../agentguard/", b"AGENTGUARD_CORE",
    # Canonical package remote. Split so this public file does not contain it verbatim.
    b"github.com/TensorScholar/" b"agentguard.git",
)


def collect(root: Path) -> dict[str, bytes]:
    candidates = [root / name for name in TOP_LEVEL]
    for name, suffixes in DIRECTORIES.items():
        directory = root / name
        if directory.is_symlink():
            raise ValueError(f"symlink directory forbidden: {name}")
        for path in sorted(directory.rglob("*")):
            relative = path.relative_to(root)
            if path.is_symlink():
                raise ValueError(f"symlink forbidden: {relative}")
            if any(part == "__pycache__" or part.startswith(".") or part.endswith(".egg-info")
                   for part in relative.parts):
                continue
            if path.is_file():
                if path.suffix not in suffixes:
                    raise ValueError(f"unapproved file type: {relative}")
                candidates.append(path)
    files = {}
    for path in sorted(candidates):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or symlink source: {path.name}")
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        if relative != "scripts/build_release.py":
            if any(marker in data for marker in FORBIDDEN):
                raise ValueError(f"publication marker detected: {relative}")
            if re.search(rb"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-",
                         data):
                raise ValueError(f"credential-like token detected: {relative}")
        files[relative] = data
    return files


def write_archive(files: dict[str, bytes], archive: Path, manifest: bytes) -> None:
    if archive.is_symlink() or (archive.exists() and not archive.is_file()):
        raise ValueError("release output must not be a symlink")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as bundle:
        for name, data in sorted({**files, "MANIFEST.sha256": manifest}.items()):
            if name.startswith("/") or name.startswith("\\") or ".." in Path(name).parts:
                raise ValueError(f"unsafe archive member: {name}")
            info = zipfile.ZipInfo("agentguard-reference/" + name, (2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, data)
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError("archive integrity failure")
        names = bundle.namelist()
        if any(item.startswith("/") or ".." in Path(item).parts for item in names):
            raise ValueError("unsafe archive member after write")
        if any(info.is_dir() is False and info.external_attr >> 16 & 0o170000 == 0o120000
               for info in bundle.infolist()):
            raise ValueError("symlink member forbidden")
        for name, data in files.items():
            if bundle.read("agentguard-reference/" + name) != data:
                raise ValueError("archive content mismatch")


def build(root: Path = ROOT, output: Path | None = None) -> tuple[Path, str, int]:
    files = collect(root)
    manifest = "".join(f"{hashlib.sha256(data).hexdigest()}  {name}\n"
                       for name, data in sorted(files.items())).encode("utf-8")
    destination = root / "release" if output is None else output
    if destination.is_symlink():
        raise ValueError("release directory must not be a symlink")
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / "agentguard-reference-final.zip"
    checksum_file = destination / (archive.name + ".sha256")
    manifest_file = destination / "manifest.sha256"
    named_manifest = destination / "agentguard-reference-final.manifest.txt"
    for path in (archive, checksum_file, manifest_file, named_manifest):
        if path.is_symlink():
            raise ValueError("release output must not be a symlink")
    write_archive(files, archive, manifest)
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_file.write_text(f"{checksum}  {archive.name}\n", encoding="utf-8")
    manifest_file.write_bytes(manifest)
    named_manifest.write_bytes(manifest)
    return archive, checksum, len(files)


if __name__ == "__main__":
    target = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
    archive, checksum, count = build(output=target)
    print(f"{archive}: {count} source files plus MANIFEST.sha256")
    print(f"SHA256 {checksum}")
