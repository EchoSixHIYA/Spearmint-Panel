"""Obtain a signed management session as part of an ordinary Grove login."""
import asyncio
import time
from types import SimpleNamespace

from . import auth, grove, grove_accounts, grove_authorization, grove_availability, grove_login
from .peer.grove_service_admin import admin_revision, parse_identity, require_member
from .peer.protocol import PeerError, wire_b64


METHOD = 'grove.login.session.v1'


def compatible(db, state, pair, request):
    require_member(db, state.identity()[0], pair)
    grove_availability.require_current(db)
    location, anchor = grove_authorization.context(db)
    scopes = request['scopes']
    now = int(time.time())
    issued = request['issued_at']
    identity = parse_identity(request['identity'])
    fields = {*location, 'identity', 'source', 'session', 'scopes', 'seed_executor', 'joining',
              'issued_at', 'expires_at', 'session_until', 'nonce'}
    if (scopes not in (grove_authorization.ADMIN_SIGNIN, grove_authorization.ACCOUNT_SIGNIN)
            or set(request) != fields or request['seed_executor'] is not None or request['joining'] is not None
            or state.identity()[0] not in anchor['voters'] or pair.node_id != request['source']
            or any(request.get(field) != value for field, value in location.items())
            or type(issued) is not int or not now - grove_authorization.LIFETIME < issued <= now + grove.CLOCK_SKEW
            or request['expires_at'] != issued + grove_authorization.LIFETIME
            or request['session_until'] != issued + auth.SESSION_SECONDS
            or identity != admin_revision(db, anchor['realm_id'], identity[1],
                                         require_admin=scopes == grove_authorization.ADMIN_SIGNIN)
            or grove_accounts.device_key(db, identity[1]) is not None
            or not db.execute('SELECT 1 FROM grove_login_verifier WHERE user_id=?', (identity[1],)).fetchone()):
        raise PeerError('DENIED', 'This voter cannot verify the requested password session')


def ballot(state, request):
    key = state.signing_key()
    data = grove_authorization.login_vote_data(request)
    return grove.signed(grove_authorization.LOGIN_VOTE,
                        {**data, 'public_key': wire_b64(key.public_key().public_bytes_raw())}, key)


def receive(state, pair, payload):
    try:
        request = payload['request']
        with state.connect(read_only=True) as db:
            db.execute('BEGIN')
            compatible(db, state, pair, request)
        if payload.keys() == {'request'}:
            return {'available': True}
        if payload.keys() != {'request', 'username', 'password', 'code'}:
            raise ValueError
        username, password, code = payload['username'], payload['password'], payload['code']
        if (not isinstance(username, str) or not 0 < len(username) <= 64
                or not isinstance(password, str) or not 0 < len(password) <= 256
                or code is not None and (not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit())):
            raise ValueError
        with grove_login.verified_password(state, username, password, code, pair.node_id) as (db, verifier, factor):
            if (verifier is not None and verifier['user_id'] == request['identity'][1]
                    and (request['scopes'] != grove_authorization.ADMIN_SIGNIN or factor)):
                compatible(db, state, pair, request)
                db.execute('DELETE FROM login_attempt WHERE address=? AND account_key=?',
                           (pair.node_id, auth.digest(username)))
                return {'vote': ballot(state, request)}
        raise PeerError('DENIED', 'The voter could not verify the Grove login')
    except auth.LoginLimited as error:
        raise PeerError('BUSY', 'The voter is limiting login attempts') from error
    except (IndexError, KeyError, TypeError, ValueError) as error:
        raise PeerError('INVALID_REQUEST', 'Invalid Grove password session') from error


def request_for(state, owner):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        row = auth.active_session(db, owner.token_hash, int(time.time()))
        if row is None or not row['grove_replica'] or row['valid_until'] != 0:
            return None
        _, anchor = grove_authorization.context(db)
        administrator = row['role'] == 'node_admin'
        if administrator and row['mfa_at'] is None:
            return None
        node = state.identity()[0]
        scopes = grove_authorization.ADMIN_SIGNIN if administrator else grove_authorization.ACCOUNT_SIGNIN
        identity = admin_revision(db, anchor['realm_id'], row['grove_user'], require_admin=administrator)
        request = grove_authorization.challenge(db, owner, node, identity, scopes)
        votes = [ballot(state, request)] if node in anchor['voters'] else []
        return request, anchor, votes


async def authorize(state, remote, token, username, password, code):
    owner = SimpleNamespace(token_hash=auth.digest(token))
    try:
        prepared = await remote.work(request_for, state, owner)
    except PeerError:
        return False
    if prepared is None:
        return False
    request, anchor, votes = prepared
    majority = len(anchor['voters']) // 2 + 1

    async def voter(node):
        try:
            # Only current voters with an existing verifier receive the
            # submitted credentials, over authenticated end-to-end TLS.
            if await remote.call(node, METHOD, {'request': request}) != {'available': True}:
                return None
            data = {'request': request, 'username': username, 'password': password, 'code': code}
            return (await remote.call(node, METHOD, data)).get('vote')
        except PeerError:
            return None

    tasks = [asyncio.create_task(voter(node)) for node in anchor['voters'] if node != remote.local_id
             and len(votes) < majority]
    try:
        async with asyncio.timeout(10):
            for reply in asyncio.as_completed(tasks):
                result = await reply
                if result:
                    votes = list(grove_authorization.verified_login_votes(anchor, request, [*votes, result]).values())
                    if len(votes) >= majority:
                        break
    except TimeoutError:
        pass
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    if len(votes) < majority:
        return False
    proof = {'grant': grove.signed(grove_authorization.GRANT, request, state.signing_key()), 'login_votes': votes}
    try:
        await remote.work(save, state, owner, proof)
    except PeerError:
        return False
    return True


def save(state, owner, proof):
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        now = int(time.time())
        if auth.active_session(db, owner.token_hash, now) is None:
            raise PeerError('DENIED', 'Grove session expired')
        grove_authorization.verify(db, proof, state.identity()[0], 'self', owner=owner, at=now)
    grove_authorization.remember_service_session(state, owner, proof, now)
