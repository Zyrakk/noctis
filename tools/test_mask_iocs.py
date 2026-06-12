"""Unit tests for mask_iocs (F1.9). Pure stdlib, no DB, no third-party deps.

Run from repo root:
    python3 -m unittest discover -s tools -p "test_*.py" -v
"""

import unittest

from mask_iocs import mask_iocs


class TestMaskIocsBasicTypes(unittest.TestCase):
    def test_ip_masked(self):
        self.assertEqual(mask_iocs("C2 at 91.92.93.94 active"),
                         "C2 at <IP> active")

    def test_ip_with_port_keeps_port(self):
        # Progressive masking: the IP is tokenised before the credential
        # regex runs, so ip:port never becomes <CRED>.
        self.assertEqual(mask_iocs("45.155.205.99:8443"), "<IP>:8443")

    def test_url_masked(self):
        self.assertEqual(mask_iocs("leak: https://mega.nz/file/x1z9"),
                         "leak: <URL>")

    def test_defanged_url_masked(self):
        self.assertEqual(mask_iocs("payload hxxps://evil-files.ru/dump.bin"),
                         "payload <URL>")

    def test_domain_masked(self):
        self.assertEqual(mask_iocs("beacons to evil-c2.ru daily"),
                         "beacons to <DOMAIN> daily")

    def test_email_masked(self):
        self.assertEqual(mask_iocs("contact ivan.petrov@mail.ru for access"),
                         "contact <EMAIL> for access")

    def test_cve_masked_case_insensitive(self):
        self.assertEqual(mask_iocs("exploits cve-2026-12345 in the wild"),
                         "exploits <CVE> in the wild")

    def test_hashes_masked(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        sha256 = ("e3b0c44298fc1c149afbf4c8996fb924"
                  "27ae41e4649b934ca495991b7852b855")
        self.assertEqual(mask_iocs(f"md5 {md5}"), "md5 <HASH>")
        self.assertEqual(mask_iocs(f"sha1 {sha1}"), "sha1 <HASH>")
        self.assertEqual(mask_iocs(f"sha256 {sha256}"), "sha256 <HASH>")

    def test_wallets_masked(self):
        eth = "0x52908400098527886E0F7030069857D2E4169EE7"
        btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        self.assertEqual(mask_iocs(f"pay to {eth}"), "pay to <WALLET>")
        self.assertEqual(mask_iocs(f"pay to {btc}"), "pay to <WALLET>")

    def test_credential_masked(self):
        self.assertEqual(mask_iocs("combo mark:opensesame works"),
                         "combo <CRED> works")


class TestPlaceholderRejection(unittest.TestCase):
    """Placeholders are example prose, not IOCs — they must stay verbatim."""

    def test_placeholder_credential_kept(self):
        self.assertEqual(mask_iocs("format is user:pass here"),
                         "format is user:pass here")

    def test_placeholder_url_and_domain_kept(self):
        self.assertEqual(mask_iocs("see http://example.com for docs"),
                         "see http://example.com for docs")

    def test_placeholder_email_kept(self):
        self.assertEqual(mask_iocs("write test@example.com"),
                         "write test@example.com")

    def test_placeholder_and_private_ips_kept(self):
        self.assertEqual(mask_iocs("dns 8.8.8.8 and lan 10.0.0.5"),
                         "dns 8.8.8.8 and lan 10.0.0.5")

    def test_degenerate_hash_kept(self):
        zeros = "0" * 64
        self.assertEqual(mask_iocs(f"dummy {zeros}"), f"dummy {zeros}")

    def test_numeric_user_not_credential(self):
        # u.isdigit() rejection from noctis_rules: timestamps aren't creds.
        self.assertEqual(mask_iocs("at 12:3456 today"), "at 12:3456 today")

    def test_pathlike_password_not_credential(self):
        self.assertEqual(mask_iocs("see notes:/etc/passwd dump"),
                         "see notes:/etc/passwd dump")


class TestMultilingualFixtures(unittest.TestCase):
    def test_russian_credential_and_ip(self):
        self.assertEqual(
            mask_iocs("слив базы, логин mark:opensesame на 91.92.93.94"),
            "слив базы, логин <CRED> на <IP>")

    def test_russian_email_combo_local_part_preserved_prose(self):
        # Email is masked first; the trailing password survives because the
        # <EMAIL> remnant reads as the placeholder user token "email".
        self.assertEqual(
            mask_iocs("база mail.ru аккаунтов: ivan@mail.ru:qwerty123"),
            "база <DOMAIN> аккаунтов: <EMAIL>:qwerty123")

    def test_persian_url(self):
        self.assertEqual(
            mask_iocs("دسترسی برای فروش hxxps://evil-files.ru/dump"),
            "دسترسی برای فروش <URL>")

    def test_chinese_domain_and_hash(self):
        md5 = "9e107d9d372bb6826bd81d3542a419d6"
        self.assertEqual(
            mask_iocs(f"样本 {md5} 回连 evil-cn.top"),
            "样本 <HASH> 回连 <DOMAIN>")

    def test_russian_placeholder_untouched(self):
        self.assertEqual(
            mask_iocs("пример: user:pass и http://example.com"),
            "пример: user:pass и http://example.com")


class TestOrderingAndEdgeCases(unittest.TestCase):
    def test_email_inside_url_collapses_into_url_token(self):
        # URLs are masked before e-mails (extract_iocs ordering); an e-mail
        # embedded in a URL path disappears inside the <URL> token.
        self.assertEqual(mask_iocs("https://x.ru/q?u=bob@corp.ru"), "<URL>")

    def test_label_colon_before_token_not_credential(self):
        # "word: <TOKEN>" must never read as a credential pair — the
        # password side starting with "<" is one of our own mask tokens.
        self.assertEqual(mask_iocs("leak: https://mega.nz/x archive"),
                         "leak: <URL> archive")
        self.assertEqual(mask_iocs("c2: 91.92.93.94"), "c2: <IP>")

    def test_url_not_double_masked_as_domain_or_cred(self):
        # The "mask URLs/e-mails first" ordering: without it the URL's
        # host:path remnants would re-match as <DOMAIN> or <CRED>.
        out = mask_iocs("read https://blog.example.com/a:bcde now")
        self.assertNotIn("<CRED>", out)
        self.assertNotIn("<DOMAIN>", out)

    def test_empty_and_none_safe(self):
        self.assertEqual(mask_iocs(""), "")
        self.assertEqual(mask_iocs(None), "")

    def test_idempotent(self):
        src = "mark:opensesame on 91.92.93.94 via https://mega.nz/x1 CVE-2026-1234"
        once = mask_iocs(src)
        self.assertEqual(mask_iocs(once), once)

    def test_text_without_iocs_unchanged(self):
        src = "Продаётся доступ к сети крупной компании, цена договорная"
        self.assertEqual(mask_iocs(src), src)


if __name__ == "__main__":
    unittest.main()
