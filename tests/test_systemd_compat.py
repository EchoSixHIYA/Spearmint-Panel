import unittest

from spearmint.systemd_compat import literal_arguments


class SystemdCompatibilityTest(unittest.TestCase):
    def test_preserves_literal_environment_references_and_spaces(self):
        arguments = ['/home/user/$HOME/bin/program', '${TOKEN}', '$$', 'a b', '', 'line\n']
        escaped = literal_arguments(arguments)
        self.assertEqual(escaped, ['/home/user/$$HOME/bin/program', '$${TOKEN}', '$$$$', 'a b', '', 'line\n'])
        self.assertEqual(arguments[1], '${TOKEN}')


if __name__ == '__main__':
    unittest.main()
