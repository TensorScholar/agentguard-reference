import hashlib
import re
import sys
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Files the published artifact must contain. Their absence is a defect.
REQUIRED_TOP_LEVEL = ("LICENSE", "README.md", "CHANGELOG.md", "SECURITY.md",
                      "Makefile", "pyproject.toml")
# Files included when present. A source distribution and an unpacked archive have no
# version-control metadata, so these must never be required.
OPTIONAL_TOP_LEVEL = (".gitignore", "MANIFEST.in")
# `scripts` is intentionally absent from DIRECTORIES: this module is the collector,
# so archiving it would ship the collector's own policy.
DIRECTORIES = {"src": {".py", ".typed"}, "tests": {".py"}, "examples": {".py", ".md"},
               "docs": {".md"}}

PEM_PATTERN = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")
HOME_PATTERN = re.compile(rb"(?:^|[\s\"'(])(?:/Users/|/home/|/root/)")
CREDENTIAL_PATTERN = re.compile(
    rb"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-|"
    rb"glpat-[A-Za-z0-9_-]{20,}")
REMOTE_PATTERN = re.compile(rb"\b[\w.-]+\.git\b")
TRAVERSAL_PATTERN = re.compile(rb"\.\./")
MARKDOWN_SUFFIXES = (".md", ".rst", ".txt")


def family_stem(root: Path = ROOT) -> bytes:
    """The package-family stem, derived from this package's own declared name.

    Deriving the stem is what lets the leakage rules below be written without ever
    spelling a private identifier. A marker that must be kept out of every tracked
    and shipped file cannot also be the marker written into a tracked or shipped
    file, so the rule is expressed against the stem this package declares for
    itself instead of against a forbidden string.
    """
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return project["project"]["name"].split("-")[0].encode("ascii")


def approved_names(stem: bytes) -> tuple[bytes, ...]:
    """Public names of this artifact that may legitimately carry the family stem.

    Matched case-insensitively, so prose capitalisation is approved too.
    """
    return (stem + b"-reference", stem + b"_reference", b"." + stem,
            stem + b" Reference", stem + b" Core")


def family_violations(data: bytes, stem: bytes | None = None) -> list[bytes]:
    """Return every family-stem reference that is not a public name of this package.

    Approved public names are removed first, so the residue is exactly the set of
    references that claim something other than this artifact -- a version-control
    remote, a sibling checkout path, or a marker token. A bare family stem used as a
    package name is not a public name of this artifact and is reported.
    """
    stem = stem if stem is not None else family_stem()
    residue = data
    for name in approved_names(stem):
        residue = re.sub(re.escape(name), b"", residue, flags=re.IGNORECASE)
    return re.findall(re.escape(stem) + rb"\S*", residue, flags=re.IGNORECASE)


def public_artifact_violations(relative: str, data: bytes) -> list[str]:
    """Reasons why ``relative`` must not enter a public artifact. Fails closed.

    Every rule is expressed with a generic shape or with a name this package
    declares for itself. No private identifier appears in this module.
    """
    reasons: list[str] = []
    if PEM_PATTERN.search(data):
        reasons.append("private-key PEM header")
    if HOME_PATTERN.search(data):
        reasons.append("user home directory path")
    if CREDENTIAL_PATTERN.search(data):
        reasons.append("credential-shaped token")
    if REMOTE_PATTERN.search(data):
        reasons.append("version-control remote")
    if not relative.endswith(MARKDOWN_SUFFIXES) and TRAVERSAL_PATTERN.search(data):
        reasons.append("parent-directory traversal outside the package")
    for reference in family_violations(data):
        reasons.append(f"non-public package-family reference {reference!r}")
    return reasons


def collect(root: Path) -> dict[str, bytes]:
    """Collect the publishable file set and apply the public-artifact policy.

    Membership is decided by an explicit allow-list of paths and file types. Content
    policy is applied to every candidate, including this module's own siblings, with
    no exemption: a scanner that exempts itself is not a scanner.
    """
    missing = [name for name in REQUIRED_TOP_LEVEL if not (root / name).is_file()]
    if missing:
        raise ValueError(f"required source missing: {', '.join(missing)}")
    candidates = [root / name for name in REQUIRED_TOP_LEVEL + OPTIONAL_TOP_LEVEL
                  if (root / name).is_file()]
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
    files: dict[str, bytes] = {}
    for path in sorted(candidates):
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing or symlink source: {path.name}")
        relative = path.relative_to(root).as_posix()
        data = path.read_bytes()
        reasons = public_artifact_violations(relative, data)
        if reasons:
            raise ValueError(f"not publishable: {relative}: {'; '.join(reasons)}")
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
