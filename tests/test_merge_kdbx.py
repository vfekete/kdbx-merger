#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#     "pykeepass>=4.1,<5",
# ]
# ///
"""Tests for merge-kdbx.

Every test builds fresh mock KDBX files in a temporary directory, runs the
merge-kdbx script as a subprocess (passwords fed through stdin) and inspects
the merged database with pykeepass.

Run:  ./tests/test_merge_kdbx.py   (or: uv run --script tests/test_merge_kdbx.py)
"""

import base64
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unicodedata
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree
from pykeepass import PyKeePass, create_database

SCRIPT = Path(__file__).resolve().parent.parent / "merge-kdbx"

PW_A = "alpha-Pässwörd-1"
PW_B = "bravo-password-2"
PW_OUT = "merged-output-pw"

OLD = datetime(2015, 3, 14, 9, 26, 53, tzinfo=timezone.utc)
EXPIRY_1 = datetime(2030, 1, 31, 12, 0, 0, tzinfo=timezone.utc)
EXPIRY_PAST = datetime(2020, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
ICON_PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n fake icon data").decode()


def group_path(kp, path):
    group = kp.root_group
    for name in path.split("/"):
        group = next((g for g in group.subgroups if g.name == name), None)
        assert group is not None, f"group {path} missing"
    return group


def entry_titles(group):
    return sorted(e.title for e in group.entries)


def entry(group, title):
    found = [e for e in group.entries if e.title == title]
    assert len(found) == 1, f"{title!r} found {len(found)}x in {group.name}"
    return found[0]


def strip_attachment_notes(notes):
    if notes is None:
        return None
    lines = [l for l in notes.split("\n") if not l.startswith("same attachment ")]
    return "\n".join(lines) or None


SAME_ATT = 'same attachment "{}" found in: file1.kdbx, file3.kdbx'


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def add_custom_icon(kp, data_b64):
    meta = kp.tree.getroot().find("Meta")
    icons = meta.find("CustomIcons")
    if icons is None:
        icons = etree.SubElement(meta, "CustomIcons")
    icon = etree.SubElement(icons, "Icon")
    icon_uuid = base64.b64encode(uuid.uuid4().bytes).decode()
    etree.SubElement(icon, "UUID").text = icon_uuid
    etree.SubElement(icon, "Data").text = data_b64
    return icon_uuid


def set_custom_icon(element, icon_uuid):
    el = element._element
    ref = etree.Element("CustomIconUUID")
    ref.text = icon_uuid
    anchor = el.find("IconID")
    if anchor is None:
        anchor = el.find("UUID") if el.find("Name") is None else el.find("Name")
    anchor.addnext(ref)


def build_file1(path):
    kp = create_database(str(path), password=PW_A)
    f1 = kp.add_group(kp.root_group, "Folder1", notes="folder one notes")
    f2 = kp.add_group(f1, "Folder2")
    banking = kp.add_group(kp.root_group, "Banking")
    scan = kp.add_group(kp.root_group, "Scan")

    item = kp.add_entry(f2, "item", "user1", "pw-item-file1", url="https://one.example",
                        notes="original item", tags=["work", "vpn"],
                        expiry_time=EXPIRY_1)
    item.expires = True
    item.set_custom_property("pin", "1234", protect=True)
    item.set_custom_property("plain", "visible")
    att = kp.add_binary(b"attachment from file1\x00\x01\x02")
    item.add_attachment(att, "f1.bin")
    item.ctime = OLD
    item.save_history()
    item.password = "pw-item-file1-new"          # history keeps the old one
    kp.add_entry(f1, "other", "u", "pw-other")
    kp.add_entry(banking, "bank", "acct", "pw-bank", notes="line1\nline2")
    kp.add_entry(kp.root_group, "Email", "me@one", "pw-email-1")
    kp.add_entry(scan, "x", "", "pw-x")
    kp.add_entry(scan, "x - 3", "", "pw-x3")          # pre-existing indexed title
    kp.save()


def build_file2(path):
    kp = create_database(str(path), password=PW_A)      # same password as file1
    f1 = kp.add_group(kp.root_group, "Folder1")
    f2 = kp.add_group(f1, "Folder2")
    item = kp.add_entry(f2, "item", "user2", "pw-item-file2", notes="from second",
                        expiry_time=EXPIRY_PAST)
    item.expires = True
    item.ctime = OLD
    att = kp.add_binary(b"attachment from file2")
    item.add_attachment(att, "f2.txt")
    kp.add_entry(f2, "newitem", "nu", "pw-new")
    new_top = kp.add_group(kp.root_group, "NewTop", notes="created by merge")
    sub = kp.add_group(new_top, "Sub")
    deep = kp.add_entry(sub, "deep", "d", "pw-deep", url="https://deep.example")
    icon = add_custom_icon(kp, ICON_PNG)
    set_custom_icon(deep, icon)
    set_custom_icon(new_top, icon)
    kp.add_entry(kp.root_group, "Email", "me@two", "pw-email-2")
    scan = kp.add_group(kp.root_group, "Scan")
    kp.add_entry(scan, "x", "", "pw-x-file2")
    kp.save()


def build_file3(path):
    kp = create_database(str(path), password=PW_B)      # different password
    f1 = kp.add_group(kp.root_group, "Folder1")
    f2 = kp.add_group(f1, "Folder2")
    item = kp.add_entry(f2, "item", "user3", "pw-item-file3")
    att = kp.add_binary(b"attachment from file1\x00\x01\x02")   # identical to file1
    item.add_attachment(att, "same.bin")
    twins = kp.add_group(kp.root_group, "Twins")
    kp.add_entry(twins, "twin", "t1", "pw-twin-1", force_creation=True)
    kp.add_entry(twins, "twin", "t2", "pw-twin-2", force_creation=True)
    banking = kp.add_group(kp.root_group, "Banking")
    sub = kp.add_group(banking, "Cards")
    kp.add_entry(sub, "visa", "4111", "pw-visa")
    kp.save()


class MergeTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="merge-kdbx-test-"))
        self.f1 = self.tmp / "file1.kdbx"
        self.f2 = self.tmp / "some" / "path2" / "file2.kdbx"
        self.f3 = self.tmp / "file3.kdbx"
        self.f2.parent.mkdir(parents=True)
        build_file1(self.f1)
        build_file2(self.f2)
        build_file3(self.f3)
        self.out = self.tmp / "merged.kdbx"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def run_merge(self, *args, stdin="", env=None, check=True):
        proc = subprocess.run(
            [str(SCRIPT), *map(str, args)], input=stdin.encode(), capture_output=True,
            cwd=self.tmp, env=env, timeout=600,
        )
        if check and proc.returncode != 0:
            self.fail(f"merge-kdbx failed ({proc.returncode}):\n{proc.stderr.decode()}")
        return proc

    def rel(self, p):
        return os.path.relpath(p, self.tmp)


class TestFullMerge(MergeTestCase):
    def setUp(self):
        super().setUp()
        self.hashes = {p: sha(p) for p in (self.f1, self.f2, self.f3)}
        self.proc = self.run_merge(
            "-i", self.rel(self.f1), self.rel(self.f2), self.rel(self.f3),
            "-ip", "user", "-o", "merged.kdbx", "-p", PW_OUT, "-v",
            stdin=f"{PW_A}\n{PW_B}\n",
        )
        self.stderr = self.proc.stderr.decode()
        self.kp = PyKeePass(str(self.out), password=PW_OUT)

    def test_password_prompts_reuse_typed_passwords(self):
        # file2 shares file1's password -> only file1 and file3 are prompted
        self.assertEqual(self.stderr.count("Password for"), 2, self.stderr)
        self.assertIn("Password for file1.kdbx", self.stderr)
        self.assertIn("Password for file3.kdbx", self.stderr)

    def test_inputs_untouched(self):
        for p, h in self.hashes.items():
            self.assertEqual(sha(p), h, p)

    def test_no_extra_files(self):
        files = sorted(self.rel(p) for p in self.tmp.rglob("*") if p.is_file())
        self.assertEqual(files, ["file1.kdbx", "file3.kdbx", "merged.kdbx",
                                 "some/path2/file2.kdbx"])
        self.assertEqual(stat.S_IMODE(self.out.stat().st_mode), 0o600)

    def test_output_password(self):
        from pykeepass.exceptions import CredentialsError
        for pw in (PW_A, PW_B):
            with self.assertRaises(CredentialsError):
                PyKeePass(str(self.out), password=pw)

    def test_first_file_copied_one_to_one(self):
        orig = PyKeePass(str(self.f1), password=PW_A)
        for e in orig.entries:
            path = "/".join(e.path[:-1]) if len(e.path) > 1 else None
            group = group_path(self.kp, path) if path else self.kp.root_group
            m = entry(group, e.title)
            self.assertEqual(m.uuid, e.uuid)
            self.assertEqual(strip_attachment_notes(m.notes), e.notes, e.title)
            for attr in ("username", "password", "url", "tags", "expires",
                         "expiry_time", "ctime", "mtime", "custom_properties", "icon"):
                self.assertEqual(getattr(m, attr), getattr(e, attr), f"{e.title}.{attr}")
            self.assertEqual(len(m.history), len(e.history))
            self.assertEqual([a.data for a in m.attachments], [a.data for a in e.attachments])
        self.assertEqual(group_path(self.kp, "Folder1").notes, "folder one notes")

    def test_item_properties_preserved(self):
        item = entry(group_path(self.kp, "Folder1/Folder2"), "item")
        self.assertEqual(item.username, "user1")
        self.assertEqual(item.password, "pw-item-file1-new")
        self.assertEqual(item.history[0].password, "pw-item-file1")
        self.assertEqual(item.custom_properties, {"pin": "1234", "plain": "visible"})
        self.assertTrue(item.is_custom_property_protected("pin"))
        self.assertEqual(item.tags, ["work", "vpn"])
        self.assertTrue(item.expires)
        self.assertEqual(item.expiry_time, EXPIRY_1)
        self.assertEqual(item.ctime, OLD)
        self.assertEqual(item.notes, "original item\n" + SAME_ATT.format("f1.bin"))

    def test_duplicates_are_indexed_with_source_notes(self):
        f2 = group_path(self.kp, "Folder1/Folder2")
        self.assertEqual(entry_titles(f2), ["item", "item - 1", "item - 2", "newitem"])

        i1 = entry(f2, "item - 1")
        self.assertEqual(i1.username, "user2")
        self.assertEqual(i1.password, "pw-item-file2")
        self.assertEqual(i1.notes, "from second\nsource: some/path2/file2.kdbx")
        self.assertTrue(i1.expires)
        self.assertEqual(i1.expiry_time, EXPIRY_PAST)    # expired entries copied too
        self.assertEqual(i1.ctime, OLD)
        self.assertEqual([(a.filename, a.data) for a in i1.attachments],
                         [("f2.txt", b"attachment from file2")])

        i2 = entry(f2, "item - 2")
        self.assertEqual(i2.password, "pw-item-file3")
        self.assertEqual(i2.notes, "source: file3.kdbx\n" + SAME_ATT.format("same.bin"))
        self.assertEqual(i2.attachments[0].data, b"attachment from file1\x00\x01\x02")

        new = entry(f2, "newitem")
        self.assertIsNone(new.notes)          # non-duplicates get no note

        root = self.kp.root_group
        self.assertEqual(entry_titles(root), ["Email", "Email - 1"])
        self.assertEqual(entry(root, "Email - 1").password, "pw-email-2")

    def test_index_continues_after_existing_highest(self):
        scan = group_path(self.kp, "Scan")
        self.assertEqual(entry_titles(scan), ["x", "x - 3", "x - 4"])
        self.assertEqual(entry(scan, "x - 4").password, "pw-x-file2")

    def test_duplicates_within_one_source(self):
        twins = group_path(self.kp, "Twins")
        self.assertEqual(entry_titles(twins), ["twin", "twin - 1"])
        self.assertEqual(entry(twins, "twin").password, "pw-twin-1")
        self.assertIsNone(entry(twins, "twin").notes)
        self.assertEqual(entry(twins, "twin - 1").notes, "source: file3.kdbx")

    def test_groups_created_and_reused(self):
        top = [g.name for g in self.kp.root_group.subgroups]
        self.assertEqual(sorted(top), ["Banking", "Folder1", "NewTop", "Scan", "Twins"])
        self.assertEqual(len([g for g in top if g == "Folder1"]), 1)
        self.assertEqual(len(group_path(self.kp, "Folder1").subgroups), 1)
        self.assertEqual(group_path(self.kp, "NewTop").notes, "created by merge")
        deep = entry(group_path(self.kp, "NewTop/Sub"), "deep")
        self.assertEqual(deep.url, "https://deep.example")
        visa = entry(group_path(self.kp, "Banking/Cards"), "visa")
        self.assertEqual(visa.password, "pw-visa")
        self.assertEqual(entry(group_path(self.kp, "Banking"), "bank").notes, "line1\nline2")

    def test_custom_icons_copied(self):
        icons = self.kp.tree.xpath("/KeePassFile/Meta/CustomIcons/Icon")
        self.assertEqual([i.findtext("Data") for i in icons], [ICON_PNG])
        icon_uuid = icons[0].findtext("UUID")
        deep = entry(group_path(self.kp, "NewTop/Sub"), "deep")
        self.assertEqual(deep._element.findtext("CustomIconUUID"), icon_uuid)
        self.assertEqual(group_path(self.kp, "NewTop")._element.findtext("CustomIconUUID"),
                         icon_uuid)

    def test_identical_attachments_deduplicated(self):
        self.assertEqual(len(self.kp.binaries), 2)

    def test_identical_attachments_noted_with_all_files(self):
        noted = sorted(e.title for e in self.kp.entries
                       if e.notes and "same attachment" in e.notes)
        self.assertEqual(noted, ["item", "item - 2"])
        # attachment present only in one file -> no note
        i1 = entry(group_path(self.kp, "Folder1/Folder2"), "item - 1")
        self.assertNotIn("same attachment", i1.notes)

    def test_all_entries_present(self):
        total = sum(len(PyKeePass(str(p), password=pw).entries)
                    for p, pw in ((self.f1, PW_A), (self.f2, PW_A), (self.f3, PW_B)))
        self.assertEqual(len(self.kp.entries), total)
        uuids = [e.uuid for e in self.kp.entries]
        self.assertEqual(len(uuids), len(set(uuids)))

    def test_order_of_inputs_determines_index(self):
        out2 = self.tmp / "reversed.kdbx"
        self.run_merge("-i", self.rel(self.f3), self.rel(self.f2), self.rel(self.f1),
                       "-o", out2, "-p", PW_OUT, stdin=f"{PW_B}\n{PW_A}\n")
        kp = PyKeePass(str(out2), password=PW_OUT)
        f2 = group_path(kp, "Folder1/Folder2")
        self.assertEqual(entry(f2, "item").password, "pw-item-file3")
        self.assertEqual(entry(f2, "item - 1").password, "pw-item-file2")
        self.assertEqual(entry(f2, "item - 2").password, "pw-item-file1-new")
        self.assertEqual(entry(f2, "item - 2").notes,
                         "original item\nsource: file1.kdbx\n"
                         'same attachment "f1.bin" found in: file3.kdbx, file1.kdbx')


class TestEdgeCases(MergeTestCase):
    def test_same_file_twice_gets_new_uuids(self):
        copy_path = self.tmp / "copy.kdbx"
        shutil.copy(self.f1, copy_path)
        self.run_merge("-i", "file1.kdbx", "copy.kdbx", "-o", self.out, "-p", PW_OUT,
                       stdin=f"{PW_A}\n")
        kp = PyKeePass(str(self.out), password=PW_OUT)
        uuids = [e.uuid for e in kp.entries]
        self.assertEqual(len(uuids), 2 * len(PyKeePass(str(self.f1), password=PW_A).entries))
        self.assertEqual(len(uuids), len(set(uuids)))
        f2 = group_path(kp, "Folder1/Folder2")
        self.assertEqual(entry_titles(f2), ["item", "item - 1"])
        dup = entry(f2, "item - 1")
        self.assertEqual(dup.notes, "original item\nsource: copy.kdbx\n"
                                    'same attachment "f1.bin" found in: file1.kdbx, copy.kdbx')
        self.assertEqual(len(dup.history), 1)
        self.assertEqual(dup.attachments[0].data, b"attachment from file1\x00\x01\x02")
        self.assertEqual(entry_titles(group_path(kp, "Scan")),
                         ["x", "x - 3", "x - 3 - 1", "x - 4"])

    def test_wrong_password_is_asked_again(self):
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                              "-p", PW_OUT, stdin=f"nope\n{PW_A}\nwrong\n{PW_B}\n")
        err = proc.stderr.decode()
        self.assertEqual(err.count("wrong password"), 2, err)
        PyKeePass(str(self.out), password=PW_OUT)

    def test_gives_up_after_three_wrong_passwords(self):
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                              "-p", PW_OUT, stdin="a\nb\nc\n", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertFalse(self.out.exists())

    def test_output_password_typed_and_retyped(self):
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                              stdin=f"{PW_A}\n{PW_B}\nfirst\nsecond\n{PW_OUT}\n{PW_OUT}\n")
        self.assertIn("do not match", proc.stderr.decode())
        PyKeePass(str(self.out), password=PW_OUT)

    def _fake_secret_tool(self, services=None):
        """Fake secret-tool; services maps the 'service' attribute to a secret."""
        bindir = self.tmp / "bin"
        bindir.mkdir()
        tool = bindir / "secret-tool"
        log = self.tmp / "bin" / "calls.log"
        lookups = "".join(
            f"""if [ "$1" = lookup ] && [ "$2" = service ] && [ "$3" = '{svc}' ]; then
    printf '%s' '{pw}'; exit 0
fi
""" for svc, pw in (services or {}).items())
        tool.write_text(f"""#!/bin/sh
echo "$@" >> '{log}'
{lookups}if [ "$1" = lookup ] && [ "$2" = service ] && [ "$3" = merge-kdbx ]; then
    printf '%s' '{PW_OUT}'; exit 0
fi
if [ "$1" = search ]; then
    printf '[/org/freedesktop/secrets/collection/login/1]\\n'
    printf 'label = other item\\nsecret = not-this-one\\n'
    printf 'created = 2025-01-01 00:00:00\\nschema = org.freedesktop.Secret.Generic\\n'
    printf '[/org/freedesktop/secrets/collection/login/2]\\n'
    printf 'label = kdbx merged\\nsecret = {PW_OUT}\\n'
    printf 'created = 2025-01-01 00:00:00\\nattribute.service = merge-kdbx\\n'
    exit 0
fi
exit 1
""")
        tool.chmod(0o755)
        env = dict(os.environ)
        env["PATH"] = f"{bindir}:{env['PATH']}"
        return env

    def test_secret_tool_by_label(self):
        env = self._fake_secret_tool()
        self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                       "-ps", "kdbx merged", stdin=f"{PW_A}\n{PW_B}\n", env=env)
        PyKeePass(str(self.out), password=PW_OUT)

    def test_secret_tool_by_attributes(self):
        env = self._fake_secret_tool()
        self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                       "-ps", "service=merge-kdbx", stdin=f"{PW_A}\n{PW_B}\n", env=env)
        PyKeePass(str(self.out), password=PW_OUT)

    def test_secret_tool_missing_label(self):
        env = self._fake_secret_tool()
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                              "-ps", "nonexistent", stdin=f"{PW_A}\n{PW_B}\n", env=env,
                              check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("no item labelled", proc.stderr.decode())
        self.assertFalse(self.out.exists())

    def test_refuses_existing_output(self):
        self.out.write_bytes(b"keep me")
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out,
                              "-p", PW_OUT, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(self.out.read_bytes(), b"keep me")

    def test_force_overwrites_output(self):
        self.out.write_bytes(b"old")
        self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", self.out, "-p", PW_OUT,
                       "--force", stdin=f"{PW_A}\n{PW_B}\n")
        PyKeePass(str(self.out), password=PW_OUT)

    def test_refuses_input_as_output(self):
        h = sha(self.f1)
        proc = self.run_merge("-i", "file1.kdbx", "file3.kdbx", "-o", "file1.kdbx",
                              "-p", PW_OUT, "--force", check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(sha(self.f1), h)

    def test_requires_two_inputs(self):
        proc = self.run_merge("-i", "file1.kdbx", "-o", self.out, "-p", PW_OUT, check=False)
        self.assertNotEqual(proc.returncode, 0)


class TestSecretToolInput(MergeTestCase):
    PIN = "1234"

    def service(self, path):
        return f"{self.PIN}-{path}"

    def merge(self, services, stdin, *extra, check=True):
        env = TestEdgeCases._fake_secret_tool(self, services)
        return self.run_merge("-i", "file1.kdbx", self.rel(self.f2), "file3.kdbx",
                              "-ip", "secret-tool", "-o", self.out, "-p", PW_OUT, *extra,
                              stdin=stdin, env=env, check=check)

    def test_all_passwords_from_secret_tool(self):
        proc = self.merge({self.service(self.f1): PW_A, self.service(self.f2): PW_A,
                           self.service(self.f3): PW_B}, stdin=f"{self.PIN}\n")
        err = proc.stderr.decode()
        self.assertEqual(err.count("secret-tool PIN"), 1)
        self.assertNotIn("Password for", err)
        kp = PyKeePass(str(self.out), password=PW_OUT)
        self.assertEqual(len(kp.entries), 6 + 5 + 4)

    def test_path_as_given_on_command_line(self):
        self.merge({self.service("file1.kdbx"): PW_A,
                    self.service(self.rel(self.f2)): PW_A,
                    self.service("file3.kdbx"): PW_B}, stdin=f"{self.PIN}\n")
        PyKeePass(str(self.out), password=PW_OUT)

    def test_missing_entry_falls_back_to_previous_passwords(self):
        # file2 has no entry, but shares file1's password
        proc = self.merge({self.service(self.f1): PW_A, self.service(self.f3): PW_B},
                          stdin=f"{self.PIN}\n")
        err = proc.stderr.decode()
        self.assertIn("no secret-tool entry for some/path2/file2.kdbx", err)
        self.assertNotIn("Password for", err)

    def test_wrong_stored_password_falls_back(self):
        proc = self.merge({self.service(self.f1): PW_A, self.service(self.f2): "stale",
                           self.service(self.f3): PW_B}, stdin=f"{self.PIN}\n")
        self.assertIn("does not work", proc.stderr.decode())
        PyKeePass(str(self.out), password=PW_OUT)

    def test_nothing_works_user_cancels(self):
        proc = self.merge({self.service(self.f1): PW_A}, stdin=f"{self.PIN}\nc\n",
                          check=False)
        err = proc.stderr.decode()
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("No working password for file3.kdbx", err)
        self.assertIn("merging cancelled at file3.kdbx", err)
        self.assertFalse(self.out.exists())

    def test_nothing_works_user_provides_password(self):
        proc = self.merge({self.service(self.f1): PW_A},
                          stdin=f"{self.PIN}\np\nwrong\np\n{PW_B}\n")
        err = proc.stderr.decode()
        self.assertIn("wrong password for file3.kdbx", err)
        PyKeePass(str(self.out), password=PW_OUT)

    def test_wrong_pin_asks_for_every_unknown_password(self):
        proc = self.merge({self.service(self.f1): PW_A, self.service(self.f3): PW_B},
                          stdin=f"9999\np\n{PW_A}\np\n{PW_B}\n")
        err = proc.stderr.decode()
        self.assertEqual(err.count("No working password"), 2)   # file2 reuses file1's
        PyKeePass(str(self.out), password=PW_OUT)

    def test_help_mentions_secret_tool_input(self):
        out = subprocess.run([str(SCRIPT), "--help"], capture_output=True).stdout.decode()
        self.assertIn("secret-tool", out)
        self.assertIn('service = "<PIN>-<absolute path of FILE>"', out)

# names that are easy to get wrong: spaces, accents, other scripts, XML and
# regex special characters, path-like characters, look-alike suffixes
TRICKY_GROUPS = [
    "Bankové účty ľščťžýáíéúäňôŕĺď",
    "Пароли и логины",
    "密码 中文",
    "パスワード・日本語",
    "  leading and trailing spaces  ",
    "multiple   inner   spaces",
    "slash/back\\slash",
    "<xml> & \"quotes\" 'apos'",
    "regex .*+?^$()[]{}|",
    "emoji 🔐🗝️",
    "Ελληνικά",
    "עברית",
]
TRICKY_TITLES = [
    "Prihlásenie do banky – Tatra",
    "Почта Яндекс",
    "微信账号",
    "ログイン情報",
    " space ",
    "a.b*(c) - 1",
    "item - x",
    "<b>&amp;</b>",
    "",
    "Ťažké ÄÖÜ ß ø å",
    "tab\there",
]
PW_UNICODE = "heslo-ľščťž-пароль-密码-パス"
DIR_UNICODE = "adresár s medzerami/Папка 文件夾"


def build_tricky(path, password, label):
    kp = create_database(str(path), password=password)
    for gname in TRICKY_GROUPS:
        g = kp.add_group(kp.root_group, gname, notes=f"notes of {gname}")
        nested = kp.add_group(g, gname)                 # same name nested
        for t in TRICKY_TITLES:
            kp.add_entry(g, t, f"user {t}", f"pw {label} {gname} {t}",
                         notes=f"{label}: {t}", force_creation=True)
        kp.add_entry(nested, TRICKY_TITLES[0], "n", f"nested {label}", force_creation=True)
    kp.save()


class TestTrickyNames(MergeTestCase):
    def setUp(self):
        super().setUp()
        self.d = self.tmp / DIR_UNICODE
        self.d.mkdir(parents=True)
        self.t1 = self.d / "prvý súbor 第一.kdbx"
        self.t2 = self.d / "второй файл 二番目.kdbx"
        build_tricky(self.t1, PW_UNICODE, "one")
        build_tricky(self.t2, PW_UNICODE, "two")
        kp = PyKeePass(str(self.t2), password=PW_UNICODE)
        # unique additions in file 2 only
        g = kp.add_group(kp.root_group, "Nový priečinok – Новая папка – 新文件夹")
        kp.add_entry(g, "Jedinečný záznam 独特", "u", "pw-unique")
        # names that only *look* like existing ones
        kp.add_group(kp.root_group, "Пароли и логины ")            # trailing space
        nfd = kp.add_group(kp.root_group, unicodedata.normalize("NFD", TRICKY_GROUPS[0]))
        kp.add_entry(nfd, "decomposed", "u", "pw-nfd")
        kp.add_group(kp.root_group, TRICKY_GROUPS[1].upper())       # different case
        kp.save()
        self.src1, self.src2 = self.rel(self.t1), self.rel(self.t2)
        kp.add_entry(kp.root_group, "Email", "u", "pw-root-email")
        kp.add_entry(kp.root_group, "EMAIL ", "u", "pw-root-email-2")
        kp.save()
        self.proc = self.run_merge("-i", self.src1, self.src2, "-o",
                                   self.d / "zlúčené 合并.kdbx",
                                   "-p", PW_UNICODE, stdin=f"{PW_UNICODE}\n")
        self.kp = PyKeePass(str(self.d / "zlúčené 合并.kdbx"), password=PW_UNICODE)

    def test_groups_matched_exactly(self):
        names = [g.name for g in self.kp.root_group.subgroups]
        for gname in TRICKY_GROUPS:
            self.assertEqual(names.count(gname), 1, gname)
            group = next(g for g in self.kp.root_group.subgroups if g.name == gname)
            self.assertEqual(group.notes, f"notes of {gname}")
            self.assertEqual([s.name for s in group.subgroups], [gname])
        # look-alikes are different names -> separate groups (no silent merge)
        self.assertIn("Пароли и логины ", names)
        self.assertIn(TRICKY_GROUPS[1].upper(), names)
        self.assertIn(unicodedata.normalize("NFD", TRICKY_GROUPS[0]), names)
        self.assertEqual(len(names), len(TRICKY_GROUPS) + 4)

    def test_lookalikes_reported_but_kept_separate(self):
        err = self.proc.stderr.decode()
        g0, g1 = TRICKY_GROUPS[0], TRICKY_GROUPS[1]
        nfd = unicodedata.normalize("NFD", g0)
        self.assertIn(f"folder {g1 + ' '!r} in (root) kept separate from {g1!r}: "
                      "differs only in spaces", err)
        self.assertIn(f"folder {g1.upper()!r} in (root) kept separate from {g1!r}: "
                      "differs only in letter case", err)
        self.assertIn(f"folder {nfd!r} in (root) kept separate from {g0!r}: "
                      "differs only in how accented characters are encoded", err)
        self.assertIn("item 'EMAIL ' in (root) kept separate from 'Email'", err)
        root_titles = sorted(e.title for e in self.kp.root_group.entries)
        self.assertEqual(root_titles, ["EMAIL ", "Email"])
        # identical names are never reported
        self.assertNotIn(f"kept separate from {TRICKY_GROUPS[2]!r}", err)

    def test_titles_indexed_and_sourced(self):
        for gname in TRICKY_GROUPS:
            group = next(g for g in self.kp.root_group.subgroups if g.name == gname)
            titles = [e.title or "" for e in group.entries]
            self.assertEqual(len(titles), 2 * len(TRICKY_TITLES), gname)
            for t in TRICKY_TITLES:
                self.assertEqual(titles.count(t), 1, (gname, t))
                self.assertEqual(titles.count(f"{t} - 1"), 1, (gname, t))
                copy_ = next(e for e in group.entries if (e.title or "") == f"{t} - 1")
                self.assertEqual(copy_.password, f"pw two {gname} {t}")
                self.assertEqual(copy_.username, f"user {t}")
                self.assertEqual(copy_.notes, f"two: {t}\nsource: {self.src2}")
                orig = next(e for e in group.entries if (e.title or "") == t)
                self.assertEqual(orig.password, f"pw one {gname} {t}")
                self.assertEqual(orig.notes, f"one: {t}")
            nested = group.subgroups[0]
            self.assertEqual(sorted(e.title for e in nested.entries),
                             [TRICKY_TITLES[0], TRICKY_TITLES[0] + " - 1"])

    def test_regex_like_title_index(self):
        # "a.b*(c) - 1" already looks indexed; its duplicate must be "... - 1 - 1"
        # and must not confuse the index of other titles
        group = next(g for g in self.kp.root_group.subgroups if g.name == TRICKY_GROUPS[8])
        titles = {e.title for e in group.entries}
        self.assertIn("a.b*(c) - 1 - 1", titles)
        self.assertIn("item - x - 1", titles)

    def test_new_unicode_group_and_lookalike_content(self):
        g = next(g for g in self.kp.root_group.subgroups
                 if g.name == "Nový priečinok – Новая папка – 新文件夹")
        self.assertEqual(entry(g, "Jedinečný záznam 独特").password, "pw-unique")
        nfd = next(g for g in self.kp.root_group.subgroups
                   if g.name == unicodedata.normalize("NFD", TRICKY_GROUPS[0]))
        self.assertEqual(entry(nfd, "decomposed").password, "pw-nfd")

    def test_secret_tool_with_unicode_paths(self):
        out = self.d / "secret-tool 合并.kdbx"
        env = TestEdgeCases._fake_secret_tool(self, {
            f"7777-{self.t1}": PW_UNICODE, f"7777-{self.t2}": PW_UNICODE})
        proc = self.run_merge("-i", self.src1, self.src2, "-ip", "secret-tool",
                              "-o", out, "-p", PW_OUT, stdin="7777\n", env=env)
        self.assertNotIn("Password for", proc.stderr.decode())
        PyKeePass(str(out), password=PW_OUT)

class TestFoldersNeverDuplicated(MergeTestCase):
    def test_same_empty_folders_in_all_inputs_created_once(self):
        paths = []
        for n in range(3):
            path = self.tmp / f"empty{n}.kdbx"
            kp = create_database(str(path), password=PW_A)
            empty = kp.add_group(kp.root_group, "Empty")
            kp.add_group(kp.add_group(empty, "Nested empty"), "Deepest 空")
            kp.add_group(kp.root_group, "Prázdny priečinok")
            if n == 2:
                # in a later file: two sibling folders with the same name
                kp.add_group(kp.root_group, "Twin folder")
                twin = kp.add_group(kp.root_group, "Twin folder")
                kp.add_entry(twin, "in twin", "u", "pw-twin")
            kp.save()
            paths.append(path.name)
        self.run_merge("-i", *paths, "-o", self.out, "-p", PW_OUT, stdin=f"{PW_A}\n")
        kp = PyKeePass(str(self.out), password=PW_OUT)
        self.assertEqual(sorted(g.name for g in kp.root_group.subgroups),
                         ["Empty", "Prázdny priečinok", "Twin folder"])
        empty = group_path(kp, "Empty")
        self.assertEqual([g.name for g in empty.subgroups], ["Nested empty"])
        self.assertEqual([g.name for g in empty.subgroups[0].subgroups], ["Deepest 空"])
        self.assertEqual(len(kp.groups), 1 + 5)           # root + 5 folders
        self.assertEqual(entry(group_path(kp, "Twin folder"), "in twin").password, "pw-twin")

    def test_same_named_folders_in_first_file_are_joined(self):
        first = self.tmp / "twins-first.kdbx"
        kp = create_database(str(first), password=PW_A)
        a1 = kp.add_group(kp.root_group, "Účty Аккаунты", notes="first notes")
        a2 = kp.add_group(kp.root_group, "Účty Аккаунты", notes="second notes")
        kp.add_entry(a1, "mail", "u1", "pw-mail-1")
        kp.add_entry(a2, "mail", "u2", "pw-mail-2")
        kp.add_entry(a2, "only in second", "u", "pw-only")
        # nested same-named folders inside both twins
        n1 = kp.add_group(a1, "Sub 子")
        n2 = kp.add_group(a2, "Sub 子")
        kp.add_group(a2, "Sub 子")                                # empty third
        kp.add_entry(n1, "deep", "d1", "pw-deep-1")
        kp.add_entry(n2, "deep", "d2", "pw-deep-2")
        # Meta reference to the folder that will disappear
        meta = kp.tree.getroot().find("Meta")
        rb = meta.find("RecycleBinUUID")
        if rb is None:
            rb = etree.SubElement(meta, "RecycleBinUUID")
        rb.text = base64.b64encode(a2.uuid.bytes).decode()
        kp.save()

        second = self.tmp / "twins-second.kdbx"
        kp = create_database(str(second), password=PW_A)
        b = kp.add_group(kp.root_group, "Účty Аккаунты")
        kp.add_entry(b, "mail", "u3", "pw-mail-3")
        kp.add_group(b, "Sub 子")
        kp.save()

        self.run_merge("-i", first.name, second.name, "-o", self.out, "-p", PW_OUT,
                       stdin=f"{PW_A}\n")
        kp = PyKeePass(str(self.out), password=PW_OUT)
        self.assertEqual([g.name for g in kp.root_group.subgroups], ["Účty Аккаунты"])
        acc = kp.root_group.subgroups[0]
        self.assertEqual(acc.uuid, a1.uuid)
        self.assertEqual(acc.notes, "first notes\nsecond notes")
        self.assertEqual(sorted(e.title for e in acc.entries),
                         ["mail", "mail - 1", "mail - 2", "only in second"])
        self.assertEqual(entry(acc, "mail").password, "pw-mail-1")
        self.assertEqual(entry(acc, "mail - 1").password, "pw-mail-2")
        self.assertEqual(entry(acc, "mail - 1").notes, "source: twins-first.kdbx")
        self.assertEqual(entry(acc, "mail - 2").password, "pw-mail-3")
        self.assertEqual(entry(acc, "mail - 2").notes, "source: twins-second.kdbx")
        self.assertEqual([g.name for g in acc.subgroups], ["Sub 子"])
        self.assertEqual(sorted(e.password for e in acc.subgroups[0].entries),
                         ["pw-deep-1", "pw-deep-2"])
        self.assertEqual(sorted(e.title for e in acc.subgroups[0].entries),
                         ["deep", "deep - 1"])
        self.assertEqual(len(kp.groups), 1 + 2)
        self.assertEqual(kp.tree.getroot().findtext("Meta/RecycleBinUUID"),
                         base64.b64encode(a1.uuid.bytes).decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
