"""Unit tests for the script heuristic. Pure stdlib."""

import unittest

from textlang import detect_script


class TestDetectScript(unittest.TestCase):
    def test_cyrillic(self):
        self.assertEqual(detect_script("Продаётся доступ к сети"), "cyrillic")

    def test_latin(self):
        self.assertEqual(detect_script("initial access for sale"), "latin")

    def test_persian_is_other(self):
        self.assertEqual(detect_script("دسترسی برای فروش"), "other")

    def test_chinese_is_other(self):
        self.assertEqual(detect_script("出售内网访问权限"), "other")

    def test_mixed_cyrillic_dominant(self):
        self.assertEqual(detect_script("слив базы via mega"), "cyrillic")

    def test_mixed_latin_dominant(self):
        self.assertEqual(detect_script("selling access to сеть corp network"),
                         "latin")

    def test_tie_prefers_cyrillic(self):
        self.assertEqual(detect_script("ок ok"), "cyrillic")

    def test_no_letters_is_other(self):
        self.assertEqual(detect_script("1.2.3.4 :: 8080"), "other")
        self.assertEqual(detect_script(""), "other")
        self.assertEqual(detect_script("🔥🔥🔥"), "other")


if __name__ == "__main__":
    unittest.main()
