#!/usr/bin/env python3
"""Generatore di SBOM (Software Bill of Materials) senza dipendenze esterne.

Scansiona una cartella di progetto, legge i file di dipendenze più comuni e
produce un SBOM in formato CycloneDX 1.6 (JSON) oppure SPDX 2.3 (JSON).

Ecosistemi supportati:
  - Python: requirements*.txt, pyproject.toml, poetry.lock, Pipfile.lock
  - Node.js: package-lock.json (v1/v2/v3), package.json (fallback)
  - Go: go.mod
  - Rust: Cargo.lock
  - Java: pom.xml
  - PHP: composer.lock
  - Ruby: Gemfile.lock

Uso:
  python3 sbom_agent/generate_sbom.py <cartella> [-f cyclonedx|spdx] [-o file]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import sys
import tomllib
import uuid
from collections import Counter
from functools import cached_property
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

TOOL_NAME = "sbom-agent"
TOOL_VERSION = "1.0.0"

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist",
    "build", "target", "vendor", ".tox", ".mypy_cache", ".pytest_cache",
}


@dataclass
class Component:
    name: str
    version: str | None
    ecosystem: str  # tipo purl: pypi, npm, golang, cargo, maven, composer, gem
    source_file: str
    scope: str = "required"  # required | optional (es. dev dependencies)
    licenses: list[str] = field(default_factory=list)
    group: str | None = None  # namespace (es. groupId Maven, scope npm)

    @cached_property
    def purl(self) -> str:
        name = self.name
        ns = self.group
        if self.ecosystem == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        if "/" in name and (self.ecosystem == "composer"
                            or (self.ecosystem == "npm" and name.startswith("@"))):
            ns, name = name.split("/", 1)
        elif self.ecosystem == "golang" and "/" in name:
            ns, name = name.rsplit("/", 1)
        path = "/".join(quote(p, safe="") for p in ns.split("/")) + "/" if ns else ""
        purl = f"pkg:{self.ecosystem}/{path}{quote(name, safe='')}"
        if self.version:
            purl += "@" + quote(self.version, safe="+")
        return purl

    @property
    def key(self) -> str:
        return self.purl.lower()


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #

_EXACT_VERSION = re.compile(r"^\d[\w.+-]*$")


def _exact_version(v) -> str | None:
    """Ritorna v solo se è una versione esatta (es. "1.2.3"), non un intervallo."""
    return v if isinstance(v, str) and _EXACT_VERSION.match(v) else None


def _load_json(path: Path):
    return json.loads(path.read_text(errors="replace"))


def _load_toml(path: Path) -> dict:
    with path.open("rb") as f:
        return tomllib.load(f)


_PEP508 = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _parse_pep508(spec: str) -> tuple[str, str | None] | None:
    spec = spec.split(";", 1)[0].strip()
    m = _PEP508.match(spec)
    if not m:
        return None
    name, constraint = m.group(1), m.group(3).strip()
    pinned = re.match(r"^===?\s*([^\s,]+)$", constraint)
    return name, (pinned.group(1) if pinned else None)


def _pep508_component(spec: str, rel: str, scope: str = "required") -> Component | None:
    parsed = _parse_pep508(spec)
    return Component(parsed[0], parsed[1], "pypi", rel, scope=scope) if parsed else None


def parse_requirements(path: Path, rel: str) -> list[Component]:
    out = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith(("#", "-", "git+", "http")):
            continue
        if c := _pep508_component(line, rel):
            out.append(c)
    return out


def parse_pyproject(path: Path, rel: str) -> list[Component]:
    data = _load_toml(path)
    out = []
    project = data.get("project", {})
    for spec in project.get("dependencies", []):
        if c := _pep508_component(spec, rel):
            out.append(c)
    for specs in project.get("optional-dependencies", {}).values():
        for spec in specs:
            if c := _pep508_component(spec, rel, scope="optional"):
                out.append(c)
    poetry = data.get("tool", {}).get("poetry", {})
    for name, ver in poetry.get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        v = ver.get("version") if isinstance(ver, dict) else ver
        out.append(Component(name, _exact_version(v), "pypi", rel))
    return out


def parse_poetry_lock(path: Path, rel: str) -> list[Component]:
    data = _load_toml(path)
    return [
        Component(p["name"], p.get("version"), "pypi", rel,
                  scope="optional" if p.get("category") == "dev" else "required")
        for p in data.get("package", [])
    ]


def parse_pipfile_lock(path: Path, rel: str) -> list[Component]:
    data = _load_json(path)
    out = []
    for section, scope in (("default", "required"), ("develop", "optional")):
        for name, info in data.get(section, {}).items():
            ver = (info.get("version") or "").lstrip("=") or None
            out.append(Component(name, ver, "pypi", rel, scope=scope))
    return out


def _npm_license(info: dict) -> list[str]:
    lic = info.get("license")
    if isinstance(lic, str):
        return [lic]
    if isinstance(lic, dict) and lic.get("type"):
        return [lic["type"]]
    return []


def parse_package_lock(path: Path, rel: str) -> list[Component]:
    data = _load_json(path)
    out = []
    if "packages" in data:  # lockfile v2/v3
        for key, info in data["packages"].items():
            if not key or "node_modules/" not in key or info.get("link"):
                continue
            name = info.get("name") or key.rsplit("node_modules/", 1)[1]
            out.append(Component(
                name, info.get("version"), "npm", rel,
                scope="optional" if info.get("dev") or info.get("optional") else "required",
                licenses=_npm_license(info)))
    else:  # lockfile v1
        def walk(deps: dict) -> None:
            for name, info in deps.items():
                out.append(Component(name, info.get("version"), "npm", rel,
                                     scope="optional" if info.get("dev") else "required"))
                walk(info.get("dependencies", {}))
        walk(data.get("dependencies", {}))
    return out


def parse_package_json(path: Path, rel: str) -> list[Component]:
    if (path.parent / "package-lock.json").exists():
        return []  # il lockfile è più preciso
    data = _load_json(path)
    out = []
    for section, scope in (("dependencies", "required"), ("devDependencies", "optional")):
        for name, ver in data.get(section, {}).items():
            out.append(Component(name, _exact_version(ver), "npm", rel, scope=scope))
    return out


def parse_go_mod(path: Path, rel: str) -> list[Component]:
    out = []
    in_block = False
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require "):].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) >= 2:
            out.append(Component(parts[0], parts[1], "golang", rel))
    return out


def parse_cargo_lock(path: Path, rel: str) -> list[Component]:
    data = _load_toml(path)
    # Pacchetti senza "source" sono i crate locali del progetto: li saltiamo.
    return [Component(p["name"], p.get("version"), "cargo", rel)
            for p in data.get("package", []) if p.get("source")]


def parse_pom(path: Path, rel: str) -> list[Component]:
    # "{*}" trova i tag con o senza namespace Maven.
    root = ET.parse(path).getroot()
    props = {}
    pe = root.find("{*}properties")
    if pe is not None:
        for child in pe:
            props[child.tag.rpartition("}")[2]] = (child.text or "").strip()

    def resolve(v: str | None) -> str | None:
        if not v:
            return None
        v = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), v.strip())
        return None if "${" in v else v

    out = []
    for dep in root.iterfind(".//{*}dependency"):
        a = dep.findtext("{*}artifactId")
        if not a:
            continue
        scope = dep.findtext("{*}scope") or ""
        out.append(Component(a, resolve(dep.findtext("{*}version")), "maven", rel,
                             scope="optional" if scope in ("test", "provided") else "required",
                             group=resolve(dep.findtext("{*}groupId"))))
    return out


def parse_composer_lock(path: Path, rel: str) -> list[Component]:
    data = _load_json(path)
    out = []
    for section, scope in (("packages", "required"), ("packages-dev", "optional")):
        for p in data.get(section, []):
            out.append(Component(p["name"], str(p.get("version", "")).lstrip("v") or None,
                                 "composer", rel, scope=scope, licenses=p.get("license", [])))
    return out


def parse_gemfile_lock(path: Path, rel: str) -> list[Component]:
    out = []
    in_specs = False
    for line in path.read_text(errors="replace").splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs and not line.startswith("    "):
            in_specs = False
        m = re.match(r"^    ([^\s(]+) \(([^)]+)\)$", line) if in_specs else None
        if m:
            out.append(Component(m.group(1), m.group(2), "gem", rel))
    return out


PARSERS = {
    "pyproject.toml": parse_pyproject,
    "poetry.lock": parse_poetry_lock,
    "Pipfile.lock": parse_pipfile_lock,
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "pom.xml": parse_pom,
    "composer.lock": parse_composer_lock,
    "Gemfile.lock": parse_gemfile_lock,
}


def find_parser(filename: str):
    if filename in PARSERS:
        return PARSERS[filename]
    if re.match(r"^requirements.*\.txt$", filename):
        return parse_requirements
    return None


def scan(root: Path) -> tuple[list[Component], list[str], list[str]]:
    """Ritorna (componenti, file letti, errori)."""
    comps: dict[str, Component] = {}
    files, errors = [], []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fn in sorted(filenames):
            parser = find_parser(fn)
            if not parser:
                continue
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            try:
                found = parser(p, rel)
            except Exception as exc:  # file malformato: lo segnaliamo e proseguiamo
                errors.append(f"{rel}: {exc}")
                continue
            files.append(rel)
            for c in found:
                existing = comps.setdefault(c.key, c)
                if c.scope == "required":
                    existing.scope = "required"
    ordered = sorted(comps.values(), key=lambda c: (c.ecosystem, (c.group or ""), c.name.lower(), c.version or ""))
    return ordered, files, errors


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def to_cyclonedx(project: str, version: str | None, comps: list[Component]) -> dict:
    components = []
    for c in comps:
        item = {"type": "library", "bom-ref": c.purl, "name": c.name, "purl": c.purl, "scope": c.scope}
        if c.group:
            item["group"] = c.group
        if c.version:
            item["version"] = c.version
        if c.licenses:
            item["licenses"] = [{"license": {"name": lic}} for lic in c.licenses]
        item["properties"] = [{"name": "sbom-agent:source-file", "value": c.source_file}]
        components.append(item)
    root_ref = f"root:{project}"
    meta_comp = {"type": "application", "bom-ref": root_ref, "name": project}
    if version:
        meta_comp["version"] = version
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION}]},
            "component": meta_comp,
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": [i["bom-ref"] for i in components]}],
    }


def _spdx_id(i: int, c: Component) -> str:
    return "SPDXRef-Package-" + re.sub(r"[^A-Za-z0-9.-]", "-", f"{c.ecosystem}-{c.name}") + f"-{i}"


def to_spdx(project: str, version: str | None, comps: list[Component]) -> dict:
    root_id = "SPDXRef-RootPackage"
    packages = [{
        "SPDXID": root_id, "name": project, "versionInfo": version or "NOASSERTION",
        "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
    }]
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root_id}]
    for i, c in enumerate(comps, 1):
        sid = _spdx_id(i, c)
        declared = " AND ".join(c.licenses) if c.licenses and all(re.match(r"^[\w.+-]+$", x) for x in c.licenses) else "NOASSERTION"
        packages.append({
            "SPDXID": sid, "name": c.name, "versionInfo": c.version or "NOASSERTION",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION", "licenseDeclared": declared, "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}],
        })
        if c.scope == "required":
            rels.append({"spdxElementId": root_id, "relationshipType": "DEPENDS_ON", "relatedSpdxElement": sid})
        else:
            rels.append({"spdxElementId": sid, "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": root_id})
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{project}-sbom",
        "documentNamespace": f"https://spdx.org/spdxdocs/{quote(project, safe='')}-{uuid.uuid4()}",
        "creationInfo": {"created": _now(), "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}"]},
        "packages": packages,
        "relationships": rels,
    }


def summary(comps: list[Component], files: list[str], errors: list[str]) -> dict:
    return {
        "total_components": len(comps),
        "by_ecosystem": dict(Counter(c.ecosystem for c in comps)),
        "dev_or_optional": sum(c.scope == "optional" for c in comps),
        "without_version": [c.name for c in comps if not c.version],
        "without_license": sum(not c.licenses for c in comps),
        "files_scanned": files,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Genera un SBOM (CycloneDX o SPDX) da una cartella di progetto.")
    ap.add_argument("path", nargs="?", default=".", help="cartella da analizzare (default: .)")
    ap.add_argument("-f", "--format", choices=["cyclonedx", "spdx"], default="cyclonedx")
    ap.add_argument("-o", "--output", help="file di output (default: stdout)")
    ap.add_argument("--name", help="nome del progetto (default: nome della cartella)")
    ap.add_argument("--version", dest="proj_version", help="versione del progetto")
    ap.add_argument("--no-dev", action="store_true", help="escludi dipendenze dev/opzionali")
    ap.add_argument("--summary", action="store_true", help="stampa un riepilogo JSON su stderr")
    args = ap.parse_args(argv)

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"Errore: {root} non è una cartella", file=sys.stderr)
        return 2
    comps, files, errors = scan(root)
    if args.no_dev:
        comps = [c for c in comps if c.scope == "required"]
    project = args.name or root.name
    doc = (to_cyclonedx if args.format == "cyclonedx" else to_spdx)(project, args.proj_version, comps)
    text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        Path(args.output).write_text(text)
    else:
        sys.stdout.write(text)
    if args.summary:
        print(json.dumps(summary(comps, files, errors), indent=2), file=sys.stderr)
    if not files:
        print("Attenzione: nessun file di dipendenze trovato.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
