import os
import pathlib
import subprocess
import unittest

from release_policy import check_version, release_tag


class ReleasePolicyTests(unittest.TestCase):
    def test_release_names(self):
        for branch in ["release/v1.5.0", "hotfix/1.5.0"]:
            self.assertEqual(release_tag(branch), "v1.5.0")
        for branch in ["feat/metrics", "release/v01.2.3", "release/v1.2.3\n", "release/v1.2.3;echo bad", "hotfix/v1.2.3.4"]:
            with self.subTest(branch=branch), self.assertRaises(ValueError):
                release_tag(branch)

    def test_main_requires_trusted_release_source(self):
        # Execute the actual workflow shell, so changes to its policy are tested.
        workflow = pathlib.Path(__file__).parents[1] / "workflows/branch-policy.yml"
        block = workflow.read_text().split("        run: |\n", 1)[1]
        script = "\n".join(line[10:] for line in block.splitlines())
        cases = [
            ("main", "develop", "owner/repo", 0),
            ("main", "release/v1.5.0", "owner/repo", 0),
            ("main", "hotfix/1.5.1", "owner/repo", 0),
            ("develop", "feat/metrics", "fork/repo", 0),
            ("main", "feat/metrics", "owner/repo", 1),
            ("main", "release/v1.5.0", "fork/repo", 1),
            ("main", "release/v1.5.0\n", "owner/repo", 1),
            ("main", "release/v01.5.0", "owner/repo", 1),
        ]
        for base, head, repository, expected in cases:
            with self.subTest(base=base, head=head, repository=repository):
                env = dict(os.environ, BASE=base, HEAD=head, HEAD_REPO=repository, GITHUB_REPOSITORY="owner/repo")
                result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_release_versions(self):
        for tag in ["v0.0.0", "v1.5.0", "v10.20.30"]:
            with self.subTest(tag=tag):
                check_version(tag)
        for tag in ["1.5.0", "v01.2.3", "v1.2.3\n", "v1.2.3;echo bad", "v1.2.3-rc.1", "v1.2.3+dirty", "v1.2.3.4"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                check_version(tag)
