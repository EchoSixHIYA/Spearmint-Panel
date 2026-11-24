"""Recover missing Mesh pins from the already trusted Grove voting members."""
from dataclasses import replace
import json
from time import time

from cryptography.hazmat.primitives.serialization import Encoding

from .. import grove, grove_continuity, grove_login, grove_voters
from ..state import audit
from . import quarantine
from .credentials import NODE_ID, RANDOM_ID, certificate, fingerprint, mesh_authorities, validate_mesh_leaf
from .grove_endpoints import trusted_members
from .mesh_policy import member_allowed
from .pairing import MAX_MEMBERS, Pair, configured, members
from .policy import require_pair
from .protocol import PeerError


METHOD = 'mesh.grove_pairing'
PROOF = 'existing-member-mesh-pin'
TTL = 90
LIMIT = 16 * 1024


def authority(db):
    realm = db.execute('SELECT * FROM grove_realm').fetchone()
    if realm is None or realm['frozen'] or not realm['manifest']:
        return None
    record = db.execute('SELECT * FROM grove_login_continuity').fetchone()
    if record is None or record['sequence'] != realm['sequence']:
        return None
    if realm['issuer_paused'] and (not realm['is_issuer'] or record['recovery_proof'] is not None):
        return None
    envelope = grove_continuity.base_envelope(json.loads(record['anchor']))
    directory = grove.directory_data(json.loads(realm['manifest']),grove.realm_data(realm),allow_expired=True)
    kind = 'login-continuity' if record['recovery_proof'] is None else 'login-recovery'
    anchor = grove_continuity.snapshot_authorization(realm,directory,envelope,kind)
    if record['recovery_proof'] is not None:
        grove_continuity.verify_recovery_votes(envelope,anchor,json.loads(record['recovery_proof']))
    anchor = grove_voters.extend(db, anchor)
    return anchor['realm_id'], grove_continuity.anchor_digest(envelope), frozenset(anchor['voters'])


def candidates(state):
    local = state.identity()[0]
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        current = authority(db)
        if current is None or not db.execute('SELECT 1 FROM mesh_profile').fetchone():
            return None
        realm, anchor, voters = current
        targets = [row[0] for row in db.execute('''SELECT m.node_id FROM grove_member m
            WHERE m.enabled=1 AND m.node_id!=? AND NOT EXISTS (SELECT 1 FROM peer p WHERE p.node_id=m.node_id)
            AND NOT EXISTS (SELECT 1 FROM grove_member_departure d WHERE d.node_id=m.node_id)
            AND NOT EXISTS (SELECT 1 FROM audit a WHERE a.event='peer.removed' AND a.target=m.node_id)
            ORDER BY m.node_id''',(local,))
            if not quarantine.contains(db,row[0])]
        return realm, anchor, voters, targets


def pin(db, policy, target, local):
    if target==local and (voter := policy.voters.get(target)):
        return voter.host, voter.leaf.public_bytes(Encoding.PEM).decode()
    pair = configured(db,target)
    if pair is None or not pair.enabled or pair.legacy or pair.mesh_id!=policy.mesh:
        raise PeerError('NOT_FOUND','This voter has no current peer certificate for the member')
    return pair.host, pair.remote_pem.decode()


def attest(state, policy, caller, params):
    target, nonce = params.get('target'), params.get('nonce')
    if (params.keys()!={'target','nonce','anchor'} or not isinstance(target,str) or NODE_ID.fullmatch(target) is None
            or not isinstance(nonce,str) or RANDOM_ID.fullmatch(nonce) is None or target==caller.node_id):
        raise PeerError('INVALID_REQUEST','Invalid Grove peer certificate request')
    local = state.identity()[0]
    with state.connect(read_only=True) as db:
        db.execute('BEGIN')
        require_pair(db,caller)
        context = authority(db)
        trust = trusted_members(db,local)
        if (policy is None or context is None or local not in context[2] or policy.voters.keys()!=context[2]
                or context[:2]!=(policy.realm,params['anchor']) or caller.legacy or caller.mesh_id!=policy.mesh
                or trust is None or trust.realm_id!=policy.realm or caller.node_id not in trust.origins or target not in trust.origins
                or any(quarantine.contains(db,node) or not member_allowed(db,policy.mesh,node) for node in (caller.node_id,target))
                or grove_login.usable_replica(db,int(time())) is None):
            raise PeerError('DENIED','A current Grove voter and active members are required')
        host, leaf = pin(db,policy,target,local)
        validate_mesh_leaf(certificate(leaf.encode()),policy.roots,target,host)
        now = int(time())
        data = {'realm':policy.realm,'mesh':policy.mesh,'anchor':context[1],'requester':caller.node_id,
                'target':target,'nonce':nonce,'host':host,'leaf':leaf,'authorities':policy.roots_pem().decode(),
                'issued_at':now,'expires_at':now+TTL}
        return {'proof':grove.signed(PROOF,data,state.signing_key())}


def install(state, target, nonce, replies):
    local = state.identity()[0]
    with state.connect(write=True) as db:
        context = authority(db)
        profile = db.execute('SELECT * FROM mesh_profile').fetchone()
        active = db.execute('SELECT 1 FROM grove_member WHERE node_id=? AND enabled=1',(target,)).fetchone()
        if (context is None or profile is None or not active or configured(db,target) or quarantine.contains(db,target)
                or not member_allowed(db,profile['mesh_id'],target)):
            return False
        if db.execute("SELECT 1 FROM audit WHERE event='peer.removed' AND target=?",(target,)).fetchone():
            return False
        if db.execute('SELECT count(*) FROM peer').fetchone()[0]>=MAX_MEMBERS:
            return False
        realm, anchor, voters = context
        expected = {'realm':realm,'mesh':profile['mesh_id'],'anchor':anchor,'requester':local,'target':target,'nonce':nonce}
        offers = {}
        now = int(time())
        for voter, reply in replies.items():
            peer = configured(db,voter)
            if (voter not in voters or not peer or not peer.enabled or peer.legacy or quarantine.contains(db,voter)
                    or not member_allowed(db,profile['mesh_id'],voter)):
                continue
            try:
                public = certificate(peer.remote_pem).public_key().public_bytes_raw()
                data = grove.verified(PROOF,reply['proof'],public,LIMIT)
                if (data.keys() != expected.keys() | {'host','leaf','authorities','issued_at','expires_at'}
                        or any(data[key]!=value for key,value in expected.items())
                        or not grove.valid_time_window(data['issued_at'],data['expires_at'],now,TTL)
                        or any(not isinstance(data[field],str) for field in ('host','leaf','authorities'))):
                    continue
                offer = data['host'], data['leaf'], data['authorities']
                offers[offer] = offers.get(offer,0)+1
            except (KeyError, TypeError, ValueError, PeerError):
                continue
        agreement = next((offer for offer,count in offers.items() if count>len(voters)//2),None)
        if agreement is None:
            return False
        host, leaf, authorities = agreement
        leaf, authorities = leaf.encode(), authorities.encode()
        old = mesh_authorities(profile['ca_pem'])
        new = mesh_authorities(authorities)
        if not {fingerprint(root) for root in old}<={fingerprint(root) for root in new}:
            raise PeerError('CONFLICT','Grove pairing cannot remove existing Mesh authorities')
        for existing in members(db).values():
            replace(existing,ca_pem=authorities).validate(local)
        pin = fingerprint(certificate(leaf))
        pair = Pair(target,profile['mesh_id'],profile['bind_ip'],profile['listen_port'],None,host,None,
                    pin,authorities,profile['local_pem'],leaf,legacy=False,routed=True)
        pair.validate(local)
        if profile['ca_pem']!=authorities:
            db.execute('UPDATE mesh_profile SET ca_pem=?',(authorities,))
        db.execute('''INSERT INTO peer (node_id,mesh_id,host,fingerprint,remote_pem,write_epoch,enabled,routed)
                      VALUES (?,?,?,?,?,lower(hex(randomblob(16))),1,1)''',(target,pair.mesh_id,host,pin,leaf))
        db.execute('INSERT INTO peer_directory(peer_id) VALUES (?)',(target,))
        audit(db,'grove-majority','local','mesh.member.autopaired',target)
    return True
