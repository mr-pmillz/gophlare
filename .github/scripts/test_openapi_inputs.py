import json
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC_FILES = tuple(f"firework-{version}-openapi.json" for version in ("v2", "v3", "v4"))


class OpenAPIInputTests(unittest.TestCase):
    def test_published_snapshots_are_present(self):
        for spec_file in SPEC_FILES:
            with self.subTest(spec_file=spec_file):
                spec = json.loads((ROOT / spec_file).read_text())
                self.assertIn("openapi", spec)
                self.assertTrue(spec["paths"])

    def test_only_published_root_snapshots_escape_json_ignore(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = pathlib.Path(directory)
            (repository / ".gitignore").write_text((ROOT / ".gitignore").read_text())
            subprocess.run(["git", "init", "--quiet", directory], check=True, capture_output=True)
            cases = [(spec_file, 1) for spec_file in SPEC_FILES]
            cases.extend((filename, 0) for filename in (
                "credentials.json",
                "config/tenant.json",
                "firework-v4-response.json",
                "firework-v5-openapi.json",
            ))
            for filename, expected in cases:
                with self.subTest(filename=filename):
                    result = subprocess.run(
                        ["git", "check-ignore", "--no-index", "--quiet", "--", filename],
                        cwd=repository,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, expected, result.stderr)
