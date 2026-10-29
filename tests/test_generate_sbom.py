import json
import tempfile
import unittest
from pathlib import Path

from sbom_agent import generate_sbom as g

FIXTURE = Path(__file__).parent / "fixtures" / "demo"


class TestScan(unittest.TestCase):
    def setUp(self):
        self.comps, self.files, self.errors = g.scan(FIXTURE)
        self.purls = {c.purl: c for c in self.comps}

    def test_files_and_errors(self):
        self.assertEqual(sorted(self.files), ["Cargo.lock", "go.mod", "package-lock.json", "requirements.txt"])
        self.assertEqual(self.errors, [])

    def test_ecosystems(self):
        for purl in [
            "pkg:pypi/requests@2.32.3", "pkg:pypi/numpy@2.1.0", "pkg:pypi/flask",
            "pkg:npm/lodash@4.17.21", "pkg:npm/%40types/node@22.5.0",
            "pkg:golang/github.com/gin-gonic/gin@v1.10.0", "pkg:cargo/serde@1.0.210",
        ]:
            self.assertIn(purl, self.purls)
        self.assertNotIn("pkg:cargo/demo@0.1.0", self.purls)  # crate locale

    def test_dev_scope(self):
        self.assertEqual(self.purls["pkg:npm/%40types/node@22.5.0"].scope, "optional")

    def test_dedup_pypi_normalization(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "requirements.txt").write_text("Foo_Bar==1.0\nfoo-bar==1.0\n")
            comps, _, _ = g.scan(Path(d))
            self.assertEqual([c.purl for c in comps], ["pkg:pypi/foo-bar@1.0"])

    def test_pom_and_gemfile(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, "pom.xml").write_text(
                '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties><j.v>5.10.0</j.v></properties>'
                "<dependencies><dependency><groupId>org.junit</groupId><artifactId>junit</artifactId>"
                "<version>${j.v}</version><scope>test</scope></dependency></dependencies></project>")
            Path(d, "Gemfile.lock").write_text("GEM\n  specs:\n    rake (13.2.1)\n      foo (>= 1)\n\nPLATFORMS\n")
            comps, _, errors = g.scan(Path(d))
            purls = {c.purl: c for c in comps}
            self.assertEqual(errors, [])
            self.assertEqual(purls["pkg:maven/org.junit/junit@5.10.0"].scope, "optional")
            self.assertIn("pkg:gem/rake@13.2.1", purls)


class TestOutput(unittest.TestCase):
    def test_cyclonedx_and_spdx(self):
        with tempfile.TemporaryDirectory() as d:
            for fmt in ("cyclonedx", "spdx"):
                out = Path(d, f"{fmt}.json")
                self.assertEqual(g.main([str(FIXTURE), "-f", fmt, "-o", str(out)]), 0)
                doc = json.loads(out.read_text())
                if fmt == "cyclonedx":
                    self.assertEqual(doc["specVersion"], "1.6")
                    refs = [c["bom-ref"] for c in doc["components"]]
                    self.assertEqual(len(refs), len(set(refs)))
                else:
                    self.assertEqual(doc["spdxVersion"], "SPDX-2.3")
                    self.assertEqual(len(doc["packages"]), 10)

    def test_no_dev(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d, "o.json")
            g.main([str(FIXTURE), "--no-dev", "-o", str(out)])
            names = [c["name"] for c in json.loads(out.read_text())["components"]]
            self.assertNotIn("@types/node", names)


if __name__ == "__main__":
    unittest.main()
