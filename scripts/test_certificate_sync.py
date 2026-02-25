#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
离线测试套件：验证证书同步脚本关键逻辑（无需下载大量证书）。
"""

import sys
import argparse
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT_DIR = Path(__file__).parent.absolute()
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import sync_certificates as sync


def _write_text(file_path: Path, content: str) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")


def build_preview_cert_info_map() -> dict:
    """构造用于页面预览的离线证书样例数据。"""
    sample_items = [
        ("Digicert Global Root G2", "DigiCert Inc", "Jan 15 12:00:00 2038 GMT"),
        ("GlobalSign Root CA", "GlobalSign nv-sa", "Jan 28 12:00:00 2028 GMT"),
        ("ISRG Root X1", "Internet Security Research Group", "Jun  4 11:04:38 2035 GMT"),
        ("Microsoft Root Certificate Authority 2011", "Microsoft Corporation", "Jul  8 20:59:09 2036 GMT"),
        ("Mozilla Demo Root", "Mozilla Test Org", "Dec 31 23:59:59 2032 GMT"),
        ("Starfield Services Root", "Starfield Technologies, Inc.", "Dec 31 23:59:59 2037 GMT"),
    ]

    cert_info_map = {}
    for idx, (cn, org, not_after) in enumerate(sample_items, start=1):
        cert_info_map[f"preview_cert_{idx:02d}"] = {
            "subject_cn": cn,
            "subject_o": org,
            "issuer_cn": cn,
            "issuer_o": org,
            "not_before": "Jan  1 00:00:00 2020 GMT",
            "not_after": not_after,
            "fingerprint": f"{idx:040d}",
        }
    return cert_info_map


def generate_preview_page(preview_path: Path) -> Path:
    """生成离线页面预览文件，供人工检查页面质量。"""
    cert_info_map = build_preview_cert_info_map()
    sync.sync_template_assets()
    preview_path.parent.mkdir(parents=True, exist_ok=True)
    sync.generate_html_page(cert_info_map, preview_path)
    return preview_path


class SyncCertificatesOfflineTests(unittest.TestCase):
    """针对 sync_certificates.py 的离线单元测试"""

    def setUp(self) -> None:
        self.temp_dir_ctx = tempfile.TemporaryDirectory()
        self.root_dir = Path(self.temp_dir_ctx.name)
        self.certs_dir = self.root_dir / "certs"
        self.temp_dir = self.root_dir / "temp"
        self.blacklist_file = self.root_dir / "blacklist.txt"

        self.certs_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        self.patches = [
            mock.patch.object(sync, "ROOT_DIR", self.root_dir),
            mock.patch.object(sync, "CERTS_DIR", self.certs_dir),
            mock.patch.object(sync, "TEMP_DIR", self.temp_dir),
            mock.patch.object(sync, "BLACKLIST_FILE", self.blacklist_file),
        ]
        for patcher in self.patches:
            patcher.start()

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temp_dir_ctx.cleanup()

    def test_is_certificate_revoked_supports_typed_and_legacy_format(self) -> None:
        _write_text(
            self.blacklist_file,
            "sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
            "cccccccccccccccccccccccccccccccccccccccc\n",
        )

        cert_info_sha1 = {
            "fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256_fingerprint": "",
        }
        cert_info_sha256 = {
            "fingerprint": "",
            "sha256_fingerprint": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        }
        cert_info_legacy = {
            "fingerprint": "cccccccccccccccccccccccccccccccccccccccc",
            "sha256_fingerprint": "",
        }
        cert_info_not_revoked = {
            "fingerprint": "dddddddddddddddddddddddddddddddddddddddd",
            "sha256_fingerprint": "",
        }

        self.assertTrue(sync.is_certificate_revoked(cert_info_sha1))
        self.assertTrue(sync.is_certificate_revoked(cert_info_sha256))
        self.assertTrue(sync.is_certificate_revoked(cert_info_legacy))
        self.assertFalse(sync.is_certificate_revoked(cert_info_not_revoked))

    def test_normalize_cert_filename_sanitizes_and_appends_fingerprint(self) -> None:
        cert_info = {
            "subject_cn": "Very*Long/Root:CA?Name With Spaces and+Symbols=1234567890",
            "subject_o": "",
            "fingerprint": "1234567890abcdef1234567890abcdef12345678",
        }
        normalized = sync.normalize_cert_filename(Path("dummy.crt"), cert_info)
        normalized_str = normalized.as_posix()

        self.assertTrue(normalized_str.endswith("_12345678.crt"))
        self.assertNotIn("*", normalized_str)
        self.assertNotIn("/", normalized_str)
        self.assertNotIn(" ", normalized_str)

    def test_generate_html_page_replaces_placeholders_and_assets_path(self) -> None:
        template = """<html>
<head><link rel=\"stylesheet\" href=\"templates/assets/ios6-settings.css\"></head>
<body>
<div>{{LAST_UPDATED}}</div>
<div>{{CERTIFICATE_COUNT}}</div>
<table>{{CERTIFICATE_LIST_REPLACED}}</table>
</body>
</html>"""
        _write_text(self.root_dir / "templates" / "index.html", template)

        cert_info_map = {
            "z_cert": {
                "subject_cn": "Z Cert",
                "subject_o": "Z Org",
                "not_after": "Jan  1 00:00:00 2030 GMT",
            },
            "a_cert": {
                "subject_cn": "A Cert",
                "subject_o": "A Org",
                "not_after": "Jan  1 00:00:00 2031 GMT",
            },
        }

        output = self.root_dir / "index.html"
        sync.generate_html_page(cert_info_map, output)
        content = output.read_text(encoding="utf-8")

        self.assertNotIn("{{LAST_UPDATED}}", content)
        self.assertNotIn("{{CERTIFICATE_COUNT}}", content)
        self.assertNotIn("{{CERTIFICATE_LIST_REPLACED}}", content)
        self.assertIn("assets/ios6-settings.css", content)
        self.assertNotIn("templates/assets/", content)
        self.assertLess(content.find("A Cert"), content.find("Z Cert"))

    def test_sync_template_assets_copies_all_files(self) -> None:
        template_assets = self.root_dir / "templates" / "assets"
        _write_text(template_assets / "a.txt", "A")
        _write_text(template_assets / "b.txt", "B")

        sync.sync_template_assets()

        self.assertTrue((self.root_dir / "assets" / "a.txt").exists())
        self.assertTrue((self.root_dir / "assets" / "b.txt").exists())

    def test_process_and_store_certs_filters_duplicate_revoked_non_selfsigned(self) -> None:
        source_dir = self.root_dir / "source"
        source_dir.mkdir(parents=True, exist_ok=True)

        cert_a = source_dir / "a.crt"
        cert_b = source_dir / "b.crt"
        cert_c = source_dir / "c.crt"
        cert_d = source_dir / "d.crt"
        for cert_file in [cert_a, cert_b, cert_c, cert_d]:
            _write_text(cert_file, "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n")

        info_map = {
            "a.crt": {"fingerprint": "fp-1", "subject_cn": "A", "subject_o": "A Org"},
            "b.crt": {"fingerprint": "fp-1", "subject_cn": "B", "subject_o": "B Org"},
            "c.crt": {"fingerprint": "fp-3", "subject_cn": "C", "subject_o": "C Org"},
            "d.crt": {"fingerprint": "fp-4", "subject_cn": "D", "subject_o": "D Org"},
        }

        def fake_get_cert_info(cert_path: Path, verbose: bool = True):
            source_name = cert_path.name.replace("temp_", "")
            return info_map[source_name]

        def fake_is_revoked(cert_info):
            return cert_info["fingerprint"] == "fp-3"

        def fake_is_self_signed(cert_path: Path, verbose: bool = True):
            return cert_path.name != "temp_d.crt"

        def fake_normalize(cert_path: Path, cert_info):
            return Path(f"{cert_info['subject_cn']}_normalized.crt")

        with mock.patch.object(sync, "get_cert_info", side_effect=fake_get_cert_info), \
             mock.patch.object(sync, "is_certificate_revoked", side_effect=fake_is_revoked), \
             mock.patch.object(sync, "is_self_signed", side_effect=fake_is_self_signed), \
             mock.patch.object(sync, "normalize_cert_filename", side_effect=fake_normalize):
            result = sync.process_and_store_certs([cert_a, cert_b, cert_c, cert_d], verbose=False)

        self.assertEqual(len(result), 1)
        self.assertIn("A_normalized", result)
        self.assertTrue((self.certs_dir / "A_normalized.crt").exists())

    def test_build_aggregate_cert_bundle_generates_offline_artifacts(self) -> None:
        _write_text(
            self.certs_dir / "one.crt",
            "-----BEGIN CERTIFICATE-----\nONE\n-----END CERTIFICATE-----\n",
        )
        _write_text(
            self.certs_dir / "two.crt",
            "-----BEGIN CERTIFICATE-----\nTWO\n-----END CERTIFICATE-----\n",
        )

        def fake_run_command(command, cwd=None, verbose=True):
            cmd = " ".join(command)
            if "pkcs12" in cmd:
                out_path = Path(command[command.index("-out") + 1])
                _write_text(out_path, "P12-DATA")
            elif "crl2pkcs7" in cmd:
                out_path = Path(command[command.index("-out") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"DER-DATA")
            elif command[0] in ("wget", "curl"):
                if "-O" in command:
                    out_path = Path(command[command.index("-O") + 1])
                else:
                    out_path = Path(command[command.index("-o") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"CAB")
            return "ok"

        with mock.patch.object(sync, "run_command", side_effect=fake_run_command):
            sync.build_aggregate_cert_bundle(verbose=False)

        aggregate = self.certs_dir / "all"
        self.assertTrue((aggregate / "cacerts.pem").exists())
        self.assertTrue((aggregate / "cacerts.crt").exists())
        self.assertTrue((aggregate / "cacerts.p12").exists())
        self.assertTrue((aggregate / "cacert.der").exists())
        self.assertTrue((aggregate / "authrootstl.cab").exists())

    def test_build_aggregate_cert_bundle_der_fallback_when_pkcs7_fails(self) -> None:
        _write_text(
            self.certs_dir / "only.crt",
            "-----BEGIN CERTIFICATE-----\nONLY\n-----END CERTIFICATE-----\n",
        )

        def fake_run_command(command, cwd=None, verbose=True):
            cmd = " ".join(command)
            if "crl2pkcs7" in cmd:
                raise RuntimeError("pkcs7 failed")
            if "openssl x509" in cmd and "-outform" in command:
                out_path = Path(command[command.index("-out") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"DER-FALLBACK")
            if "pkcs12" in cmd:
                out_path = Path(command[command.index("-out") + 1])
                _write_text(out_path, "P12")
            if command[0] in ("wget", "curl"):
                if "-O" in command:
                    out_path = Path(command[command.index("-O") + 1])
                else:
                    out_path = Path(command[command.index("-o") + 1])
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_bytes(b"CAB")
            return "ok"

        with mock.patch.object(sync, "run_command", side_effect=fake_run_command):
            sync.build_aggregate_cert_bundle(verbose=False)

        self.assertTrue((self.certs_dir / "all" / "cacert.der").exists())


def main() -> int:
    parser = argparse.ArgumentParser(description="离线测试套件（含可视化预览页面生成）")
    parser.add_argument(
        "--no-preview",
        action="store_true",
        help="仅运行单元测试，不生成页面预览",
    )
    parser.add_argument(
        "--preview-path",
        default="index.test-preview.html",
        help="预览页面输出路径（默认：项目根目录 index.test-preview.html）",
    )
    args = parser.parse_args()

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(SyncCertificatesOfflineTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)

    if not result.wasSuccessful():
        return 1

    if not args.no_preview:
        output_path = (sync.ROOT_DIR / args.preview_path).resolve()
        generated = generate_preview_page(output_path)
        print(f"\n预览页面已生成: {generated}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
