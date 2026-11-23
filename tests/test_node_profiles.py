"""Functional replication of display settings across isolated Grove members."""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from spearmint import grove, grove_metadata as metadata
from spearmint.peer.protocol import decode_json, parse_b64, wire_b64
from spearmint.state import State


class NodeProfilesTest(unittest.TestCase):
    def setUp(self):
        root=Path.cwd()/'work/tmp/node-profiles/tests'
        root.mkdir(parents=True,exist_ok=True)
        self.temporary=TemporaryDirectory(dir=root)
        self.states=[State(Path(self.temporary.name)/str(index)) for index in range(3)]
        for state in self.states: state.initialize(lambda:'fixture')
        self.a,self.b,self.c=self.states
        self.ids=[state.identity()[0] for state in self.states]
        self.realm='grv1-'+'a'*32
        for state in self.states:
            with state.connect(write=True) as db:
                db.execute('''INSERT INTO grove_realm(singleton,id,name,public_key,issuer_node,issuer_origin,is_issuer)
                              VALUES(1,?,?,?,?,?,0)''',(self.realm,'Fixture',self.a.identity()[1],self.ids[0],'https://fixture.test'))
                for index,node in enumerate(self.ids):
                    db.execute('INSERT INTO grove_member(node_id,origin,enabled) VALUES(?,?,1)',(node,f'https://fixture-{index}.test'))
        self.actor=SimpleNamespace(operation_actor='fixture',address='local')

    def tearDown(self):
        self.temporary.cleanup()

    def records(self,state):
        with state.connect(read_only=True) as db:
            return [['note',json.loads(row['envelope'])] for row in db.execute('SELECT envelope FROM grove_node_note')]

    def sync(self,source,target):
        metadata.merge(target,self.realm,self.records(source))

    def test_profile_and_legacy_name_projection_survive_reopen(self):
        node=self.ids[2]
        result=metadata.save_profile(self.a,self.actor,node,'AGX Orin',node_type='edge',icon='cpu')
        self.assertEqual(result,{'note':'AGX Orin','node_type':'edge','icon':'cpu'})
        self.assertEqual(metadata.notes(self.a)[node],'AGX Orin')
        reopened=State(self.a.directory)
        reopened.verify()
        self.assertEqual(metadata.profiles(reopened)[node],result)

    def test_relay_and_offline_catchup_do_not_depend_on_the_editing_node(self):
        node=self.ids[2]
        first=metadata.save_profile(self.a,self.actor,node,'Workstation',node_type='workstation',icon='auto')
        self.sync(self.a,self.b)
        self.assertEqual(metadata.profiles(self.b)[node],first)
        metadata.save_profile(self.a,self.actor,node,'Training',node_type='workstation',icon='cloud')
        self.sync(self.a,self.b)
        # A is now absent. B supplies the latest record when C comes back online.
        self.sync(self.b,self.c)
        self.assertEqual(metadata.profiles(self.c)[node],metadata.profiles(self.b)[node])
        self.assertEqual(metadata.profiles(self.c)[node]['icon'],'cloud')

    def test_concurrent_edits_converge_and_next_edit_advances_revision(self):
        node=self.ids[2]
        metadata.save_profile(self.a,self.actor,node,'Edge',node_type='edge',icon='auto')
        metadata.save_profile(self.b,self.actor,node,'PC',node_type='pc',icon='monitor')
        left,right=self.records(self.a),self.records(self.b)
        metadata.merge(self.a,self.realm,right);metadata.merge(self.b,self.realm,left)
        self.assertEqual(metadata.profiles(self.a),metadata.profiles(self.b))
        newest=metadata.save_profile(self.b,self.actor,node,'NAS',node_type='nas',icon='hard-drive')
        self.sync(self.b,self.a);self.sync(self.a,self.c)
        self.assertEqual(metadata.profiles(self.c)[node],newest)

    def test_note_only_edit_preserves_type_and_custom_icon(self):
        node=self.ids[1]
        metadata.save_profile(self.a,self.actor,node,'GPU',node_type='workstation',icon='cloud')
        metadata.save_note(self.a,self.actor,node,'Renamed')
        profile=metadata.profiles(self.a)[node]
        self.assertEqual(profile,{'note':'Renamed','node_type':'workstation','icon':'cloud'})
        metadata.save_note(self.a,self.actor,node,'')
        self.assertEqual(metadata.profiles(self.a)[node],{**profile,'note':''})

    def test_existing_note_records_have_default_appearance(self):
        node=self.ids[1];author,public=self.a.identity()
        document=grove.signed(metadata.NOTE,{'realm':self.realm,'author':author,'public_key':wire_b64(public),
                    'node':node,'revision':1,'note':'Existing server'},self.a.signing_key())
        metadata.merge(self.b,self.realm,[['note',document]])
        self.assertEqual(metadata.profiles(self.b)[node],{'note':'Existing server','node_type':'generic','icon':'auto'})
        metadata.save_note(self.b,self.actor,node,'Old note API')
        payload=decode_json(parse_b64(self.records(self.b)[0][1]['record'],2048))
        self.assertNotIn('node_type',payload)


if __name__=='__main__': unittest.main()
