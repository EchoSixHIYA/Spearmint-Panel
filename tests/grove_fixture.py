"""Owned three-voter Grove snapshots for functional partition simulations."""
import json
from pathlib import Path
from types import SimpleNamespace
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pyotp import TOTP

from spearmint import auth, grove, grove_authorization, grove_continuity, grove_login
from spearmint.peer.protocol import wire_b64
from spearmint.state import State


class GroveFixture:
    def __init__(self, root: Path, *, member_origins: dict[int, str] | None = None):
        self.now = int(time.time())
        self.password = 'owned-fixture-password'
        self.password_hash = auth.PASSWORD.hash(self.password)
        self.secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP'
        self.owner = State(root / 'owner')
        self.owner.initialize(lambda: self.password_hash)
        self.states = [State(root / ('voter-' + str(i))) for i in range(3)]
        self.voters = sorted(state.initialize(lambda: self.password_hash) for state in self.states)
        owner_id, owner_key = self.owner.identity()
        self.realm = {'version': 1, 'id': 'grv1-' + 'a' * 32, 'name': 'Partition fixture',
            'public_key': wire_b64(owner_key), 'issuer_node': owner_id, 'issuer_origin': 'https://issuer.example:18443'}
        self.users = [{'id': 'usr1-' + value * 32, 'name': name, 'role': role,
            'enabled': True, 'epoch': 1, 'require_mfa': True} for value, name, role in
            [('1', 'admin', 'node_admin'), ('2', 'operator', 'remote_operator')]]
        member_origins = member_origins or {}
        origins = {state.identity()[0]: member_origins.get(i, f'https://voter-{i}.example:18443')
                   for i, state in enumerate(self.states)}
        origins[owner_id] = self.realm['issuer_origin']
        self.directory = {'version': 1, 'realm': self.realm, 'sequence': 1, 'issued_at': self.now,
            'expires_at': self.now + grove.DIRECTORY_TTL, 'users': self.users,
            'members': [{'node_id': node, 'origin': origin, 'enabled': 1} for node, origin in sorted(origins.items())]}
        records = [{'profile': user, 'password_hash': self.password_hash, 'totp': self.secret} for user in self.users]
        self.anchor = {'realm_id': self.realm['id'], 'sequence': 1, 'directory_sha256': grove_login.snapshot_digest(self.directory),
            'verifiers_sha256': grove_login.verifier_digest(records), 'voters': self.voters}
        self.envelope = grove.signed('login-continuity', self.anchor, self.owner.signing_key())
        self.manifest = grove.signed('directory', self.directory, self.owner.signing_key())
        for state in self.states:
            with state.connect(write=True) as db:
                db.execute('''INSERT INTO grove_realm(singleton,id,name,public_key,issuer_node,issuer_origin,is_issuer,sequence,manifest)
                    VALUES(1,?,?,?,?,?,0,1,?)''', (self.realm['id'], self.realm['name'], owner_key, owner_id,
                    self.realm['issuer_origin'], json.dumps(self.manifest)))
                db.executemany('INSERT INTO grove_member VALUES(?,?,1)', origins.items())
                grove_login.import_snapshot(state, db, self.directory, records, self.anchor['verifiers_sha256'])
                db.execute('INSERT INTO grove_login_continuity(singleton,sequence,anchor,lease_until) VALUES(1,1,?,?)',
                           (json.dumps(self.envelope), self.now + grove.DIRECTORY_TTL))
                grove_continuity.verified_anchor(db, self.envelope)

    def login(self, index=0, username='admin'):
        state = self.states[index]
        token, _ = grove_login.login(state, username, self.password, TOTP(self.secret).now(), '127.0.0.1')
        actor = auth.actor_for(state, token, '127.0.0.1')
        if username == 'admin':
            self.authorize(state, actor, username)
        return actor

    def authorize(self, state, actor=None, username='admin', scopes=None, signer=None, **kwargs):
        from spearmint.peer.grove_service_admin import admin_revision

        from spearmint import grove_accounts, grove_device_login
        signer = signer or Ed25519PrivateKey.generate()
        key = wire_b64(signer.public_key().public_bytes_raw())
        owner = actor or SimpleNamespace(token_hash=b'owned-fixture-authorization')
        if scopes is None:
            scopes = sorted(grove_authorization.KINDS - {'join', 'signin'}) if username == 'admin' else ['self']
        with state.connect(read_only=True) as db:
            db.execute('BEGIN')
            _, anchor = grove_authorization.context(db)
            user = grove_device_login.profile_for(db, username)['id']
            device = grove_accounts.device_key(db, user)
            identity = admin_revision(db, self.realm['id'], user, require_admin=False)
            request = grove_authorization.challenge(db, owner, state.identity()[0], identity, scopes, **kwargs)
        approvals = [grove_authorization.key_vote(voter, username, key)
                     for voter in getattr(self, 'all_states', self.states) if voter.identity()[0] in anchor['voters']] if not device else []
        proof = grove_authorization.issue(signer, request, approvals)
        if actor:
            grove_authorization.enrollment(state, actor, proof)
        return proof

    def expire_freshness(self, seconds=600):
        for state in self.states:
            with state.connect(write=True) as db:
                db.execute('UPDATE grove_login_continuity SET lease_until=?', (self.now - seconds,))
