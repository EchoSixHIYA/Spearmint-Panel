from io import BytesIO
from struct import pack, pack_into
import unittest

from scripts.linux_compatibility import glibc_requirements, verify_linux_glibc


def elf_with_requirement(label):
    """An ELF64 fixture with .dynstr and one GNU version need record."""
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    pack_into('<Q', header, 40, 64)
    pack_into('<HH', header, 58, 64, 3)
    strings = b'\x00libc.so.6\x00' + label + b'\x00'
    sections = bytearray(192)
    pack_into('<I', sections, 64 + 4, 3)
    pack_into('<QQ', sections, 64 + 24, 256, len(strings))
    pack_into('<I', sections, 128 + 4, 0x6ffffffe)
    pack_into('<QQI', sections, 128 + 24, 256 + len(strings), 32, 1)
    version = pack('<HHIII', 1, 1, 1, 16, 0) + pack('<IHHII', 0, 0, 2, 11, 0)
    return BytesIO(header + sections + strings + version)


class LinuxCompatibilityTest(unittest.TestCase):
    def test_accepts_minimum_abi(self):
        self.assertEqual(glibc_requirements(elf_with_requirement(b'GLIBC_2.17')), {(2, 17)})
        verify_linux_glibc(elf_with_requirement(b'GLIBC_2.17'), 'libpython')

    def test_rejects_newer_dependencies(self):
        for label in (b'GLIBC_2.18', b'GLIBC_2.26', b'GLIBC_2.35', b'GLIBC_2.38'):
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'requires GLIBC_'):
                verify_linux_glibc(elf_with_requirement(label), 'libpython')

    def test_rejects_new_named_abi(self):
        with self.assertRaisesRegex(ValueError, 'GLIBC_ABI_DT_RELR'):
            verify_linux_glibc(elf_with_requirement(b'GLIBC_ABI_DT_RELR'), 'library')

    def test_checks_only_native_files_and_rejects_truncated_elf(self):
        verify_linux_glibc(BytesIO(b'ordinary data'), 'data')
        with self.assertRaises(ValueError):
            verify_linux_glibc(BytesIO(b'\x7fELF'), 'broken library')

    def test_release_checks_amd64_and_arm64_library_contents(self):
        from scripts.verify_release import read_entries
        for target in ('linux-amd64', 'linux-arm64'):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'requires GLIBC_2.38'):
                read_entries(['spearmint/_internal/libpython3.12.so.1.0'],
                             lambda name: elf_with_requirement(b'GLIBC_2.38'), target)


if __name__ == '__main__':
    unittest.main()
