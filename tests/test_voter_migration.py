"""Voter persistence keeps the schema supported by existing group updaters."""
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from spearmint.maintenance import migrate_offline, verify_backup
from spearmint.state import State, audit
from spearmint import grove_voters


class VoterMigrationTest(unittest.TestCase):
    def test_migration_keeps_verified_schema30_rollback_snapshot(self):
        root = Path.cwd() / 'work/tmp/grove-voters/migration'
        root.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=root) as temporary:
            directory = Path(temporary)
            state = State(directory / 'state')
            node = state.initialize(lambda: 'owned-fixture-password-hash')
            with state.connect(write=True) as db:
                audit(db, 'fixture', 'local', 'fixture.before_voter_migration', node)
            snapshot = directory / 'before-voters'
            self.assertEqual(migrate_offline(state, snapshot), node)
            self.assertEqual(state.verify_schema()[1], 30)
            self.assertEqual(State(snapshot).verify_schema(allow_older=True)[1], 30)
            self.assertEqual(verify_backup(snapshot)['node_id'], node)
            with state.connect(read_only=True) as db:
                self.assertIsNotNone(db.execute("SELECT 1 FROM audit WHERE event='fixture.before_voter_migration'").fetchone())
                self.assertEqual(grove_voters.local_state(db)['jobs'], {})


if __name__ == '__main__':
    unittest.main()
