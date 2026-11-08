import importlib.util
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("development_server", Path(__file__).with_name("serve_local_development.py"))
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PublicDevelopmentRoutes(unittest.TestCase):
    def test_only_public_selected_files_are_mapped(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd(), prefix=".development-routes-") as directory:
            root = Path(directory)
            dist, stage = root / "dist", root / "stage"
            sources = {"a" * 32: {"appId": "b" * 52, "metadata": str(root / "source/metadata.json")}}
            route = lambda p: MODULE.public_file(p, dist, stage, sources)
            self.assertEqual(route("/"), dist / "index.html")
            self.assertEqual(route("/apps/index.json"), stage / "apps/index.json")
            self.assertEqual(route("/packages/" + "a" * 32), stage / "packages" / ("a" * 32))
            for path in ["/config.json", "/grain-key-root", "/packages/not-selected",
                         "/assets/../../grain-key-root", "/assets/%2e%2e/%2e%2e/grain-key-root",
                         "/screenshots/unknown/file.png"]:
                self.assertIsNone(route(path), path)


if __name__ == "__main__":
    unittest.main()
