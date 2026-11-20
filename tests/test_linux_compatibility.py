from io import BytesIO
from struct import pack, pack_into
import unittest

from scripts.linux_compatibility import glibc_requirements, verify_arm64_glibc


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
    def test_accepts_jammy_abi(self):
        self.assertEqual(glibc_requirements(elf_with_requirement(b'GLIBC_2.35')), {(2, 35)})
        verify_arm64_glibc(elf_with_requirement(b'GLIBC_2.35'), 'libpython')

    def test_rejects_noble_python_runtime(self):
        with self.assertRaisesRegex(ValueError, 'requires GLIBC_2.38'):
            verify_arm64_glibc(elf_with_requirement(b'GLIBC_2.38'), 'libpython')

    def test_rejects_new_named_abi(self):
        with self.assertRaisesRegex(ValueError, 'GLIBC_ABI_DT_RELR'):
            verify_arm64_glibc(elf_with_requirement(b'GLIBC_ABI_DT_RELR'), 'library')

    def test_checks_only_native_files_and_rejects_truncated_elf(self):
        verify_arm64_glibc(BytesIO(b'ordinary data'), 'data')
        with self.assertRaises(ValueError):
            verify_arm64_glibc(BytesIO(b'\x7fELF'), 'broken library')


if __name__ == '__main__':
    unittest.main()
