"""Login-page availability metadata using isolated account records."""
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time
import unittest

from spearmint import accounts, auth, onboarding
from spearmint.onboarding import write_private
from spearmint.state import State


class LoginAvailabilityTest(unittest.TestCase):
    def setUp(self):
        root = Path.cwd() / 'work/tmp/identity-recovery-entry/tests'
        root.mkdir(parents=True, exist_ok=True)
        self.temporary = TemporaryDirectory(dir=root)
        self.state = State(Path(self.temporary.name) / 'state')
        self.password = auth.PASSWORD.hash('fixture-only-password')
        self.state.initialize(lambda: self.password)

    def tearDown(self):
        self.temporary.cleanup()

    def test_independent_account_and_disabled_account(self):
        self.assertTrue(auth.local_login_available(self.state))
        with self.state.connect(write=True) as db:
            db.execute('UPDATE panel_account SET enabled=0')
        self.assertFalse(auth.local_login_available(self.state))
        accounts.add(self.state, 'maintenance', self.password, 'node_admin')
        self.assertTrue(auth.local_login_available(self.state))

    def test_imported_grove_account_has_no_local_entry(self):
        with self.state.connect(write=True) as db:
            account = auth.bootstrap_account(db)
            db.execute('INSERT INTO grove_account VALUES (?,?,?,?,?)',
                       (account['id'], 'usr1-' + 'a' * 32, 'admin', 1, 0))
        self.assertFalse(auth.local_login_available(self.state))

    def test_unfinished_generated_password_is_not_a_registered_local_account(self):
        record = {'version': 1, 'token': secrets.token_urlsafe(32), 'initial_hash': self.password,
                  'expires_at': int(time.time()) + 300}
        write_private(self.state.directory / onboarding.RECORD, json.dumps(record).encode())
        self.assertFalse(auth.local_login_available(self.state))
        with self.state.connect(write=True) as db:
            db.execute('UPDATE panel_account SET password_hash=?', (auth.PASSWORD.hash('chosen-password'),))
        self.assertTrue(auth.local_login_available(self.state))


if __name__ == '__main__':
    unittest.main()
