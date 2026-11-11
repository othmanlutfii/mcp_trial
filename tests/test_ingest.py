import unittest
from unittest.mock import patch

from secbot import ingest


class IngestTests(unittest.TestCase):
    def test_locked_vector_database_reports_how_to_recover(self):
        with patch.object(ingest, "load_documents", return_value=[]), patch.object(
            ingest.os.path, "exists", return_value=True
        ), patch.object(
            ingest.shutil,
            "rmtree",
            side_effect=PermissionError("file is used by another process"),
        ), patch.object(ingest.Chroma, "from_documents") as from_documents:
            with self.assertRaisesRegex(
                ingest.VectorStoreInUseError,
                "Tutup aplikasi/chatbot atau proses Python lain",
            ):
                ingest.build_index()

        from_documents.assert_not_called()

    def test_cli_prints_actionable_message_for_locked_index(self):
        with patch.object(
            ingest, "build_index", side_effect=ingest.VectorStoreInUseError("tutup aplikasi")
        ):
            with self.assertRaisesRegex(SystemExit, "tutup aplikasi"):
                ingest.main()


if __name__ == "__main__":
    unittest.main()
