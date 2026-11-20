"""Functional scheduling, multiplexing and retirement with local session fixtures."""
import asyncio
import json
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from spearmint.peer.adaptive import AdaptiveRoutes, Binding, COOLDOWN, MAX_TRIALS
from spearmint.peer.path_selection import Latency, Selector
from spearmint.peer.protocol import PeerError, wire_b64
from spearmint.peer.relay import CIRCUITS, PRIMARY_RESERVE, Circuit, Relay
from spearmint.peer.routing import Route
from spearmint.peer.session import RELAY_QUEUE_CIRCUITS, Session


class Fixture:
    def __init__(self):
        self.now = 100.
        self.manager = SimpleNamespace(local_id='company', pairs={}, neighbors={})
        self.options, self.circuits, self.incoming, self.opened = {}, {}, {}, []
        self.routing = SimpleNamespace(routes=lambda node:self.options.get(node,[]),refresh=lambda _:None,
                                       invalidate=lambda _:None,cache={})
        self.relay = SimpleNamespace(circuits=self.circuits,live=lambda circuit:circuit.identity in self.circuits,
                                     drop=self.drop,promote=lambda *_:None,incoming=lambda node:self.incoming.get(node,[]),
                                     open_route=self.open_route)
        self.scheduler = AdaptiveRoutes(self.manager,self.routing,self.relay,self.prepare,clock=lambda:self.now)

    def route(self,*hops,first_rtt=20):
        target=hops[-1]
        self.manager.pairs.setdefault(target,SimpleNamespace(node_id=target,enabled=True,routed=True,legacy=False))
        latency=Latency()
        for age in (10,5,0): latency.add(first_rtt,self.now-age)
        first=SimpleNamespace(pair=SimpleNamespace(node_id=hops[0]),generation=hops[0],session=SimpleNamespace(latency=latency))
        return Route(('company',*hops),first,ticket=object())

    def binding(self,route,rtt=100,*,identity=None,samples=3,incoming=False):
        latency=Latency()
        for index in range(samples): latency.add(rtt,self.now-(samples-index-1)*5)
        session=SimpleNamespace(latency=latency,pending={},handling=set(),write_bytes=0,closed=False,
                                created_at=self.now-12,last_business=self.now,call=AsyncMock(return_value={'status':'ok'}))
        session.link_metrics=lambda:latency.public_data(self.now)
        circuit=SimpleNamespace(identity=identity or str(len(self.circuits)),path=route.path[::-1] if incoming else route.path,
                                session=session,created=self.now-12,role='inbound' if incoming else 'trial')
        self.circuits[circuit.identity]=circuit
        if incoming: self.incoming.setdefault(route.path[-1],[]).append((route,circuit))
        return Binding(route,session,circuit)

    def primary(self,route,rtt=100,**kwargs):
        binding=self.binding(route,rtt,**kwargs)
        node=route.path[-1]
        self.scheduler.active[node]=binding
        self.scheduler.selectors[node]=Selector()
        self.scheduler.selectors[node].choose(binding.candidate(),self.now-30,'initial')
        self.scheduler.touch(node)
        return binding

    def drop(self,circuit,code):
        self.circuits.pop(circuit.identity,None)

    async def prepare(self,pair,binding,commit,check=None):
        if check: check()
        commit()

    async def open_route(self,pair,route,*,role):
        self.opened.append(route.path)
        return self.binding(route,40,samples=0).circuit

    async def step(self):
        self.scheduler.watch_statuses()
        await self.scheduler.step()
        tasks=[*self.scheduler.opening.values(),*self.scheduler.switching.values(),*self.scheduler.keepers.values()]
        if tasks: await asyncio.gather(*tasks)
        await asyncio.sleep(0)


class RouteSchedulingTest(unittest.IsolatedAsyncioTestCase):
    def relay(self):
        manager=SimpleNamespace(local_id='company',pairs={'target':SimpleNamespace(enabled=True)},forwarding_enabled=True)
        return Relay(manager,SimpleNamespace(invalidate=lambda _:None),AsyncMock())

    async def test_one_origin_can_register_128_circuits(self):
        relay=self.relay()
        for index in range(CIRCUITS):
            relay.register(SimpleNamespace(identity=str(index),path=('company','target'),role='active'))
        self.assertEqual(CIRCUITS,128)
        self.assertEqual(len(relay.circuits),128)
        with self.assertRaises(PeerError):
            relay.register(SimpleNamespace(identity='next',path=('company','target'),role='active'))

    async def test_trials_leave_reserved_primary_capacity(self):
        relay=self.relay()
        for index in range(CIRCUITS-PRIMARY_RESERVE):
            relay.register(SimpleNamespace(identity=str(index),path=('company','target'),role='trial'))
        with self.assertRaises(PeerError):
            relay.register(SimpleNamespace(identity='trial',path=('company','target'),role='trial'))
        for index in range(PRIMARY_RESERVE):
            relay.register(SimpleNamespace(identity='primary'+str(index),path=('company','target'),role='active'))
        self.assertEqual(len(relay.circuits),128)

    async def test_physical_link_multiplexes_128_channel_queues(self):
        session=Session(None,None,AsyncMock(),control=lambda _:None,relay=True)
        for index in range(128):
            session.send({'type':'relay.data','circuit_id':f'{index:032x}','sequence':0,'data':wire_b64(b'fixture')})
        self.assertEqual(RELAY_QUEUE_CIRCUITS,128)
        self.assertEqual(len(session.relay_writes),128)

    async def test_128_channels_share_writer_fairly_with_normal_rpc(self):
        frames=[];finished=asyncio.Event()
        async def send(wire):
            frames.append(json.loads(wire[4:]))
            if len(frames)==257: finished.set()
            await asyncio.sleep(0)
        session=Session(None,None,AsyncMock(),control=lambda _:None,relay=True,send_wire=send)
        for index in range(128):
            for sequence in range(2):
                session.send({'type':'relay.data','circuit_id':f'{index:032x}','sequence':sequence,'data':wire_b64(b'fixture')})
        session.send({'type':'request','id':'f'*32,'method':'peer.ping','params':{}})
        writer=asyncio.create_task(session.write_frames())
        try:
            await asyncio.wait_for(finished.wait(),3)
            data=[frame for frame in frames if frame['type']=='relay.data']
            self.assertEqual(len({frame['circuit_id'] for frame in data[:128]}),128)
            self.assertTrue(all(frame['sequence']==0 for frame in data[:128]))
            self.assertEqual(frames[0]['type'],'request')
        finally:
            writer.cancel();await asyncio.gather(writer,return_exceptions=True)

    async def test_verified_standbys_do_not_occupy_sampling_slots(self):
        f=Fixture()
        for target in ('a','b','nas'):
            route=f.route('us',target)
            f.primary(route,900)
            f.options[target]=[route]
            if target!='nas':
                alternative=f.route('other',target)
                f.scheduler.trials[target]=f.binding(alternative,950)
                f.options[target].append(alternative)
        better=f.route('shanghai','nas')
        f.options['nas'].append(better)
        await f.step()
        self.assertEqual(f.opened,[better.path])
        self.assertEqual(len(f.circuits),6)
        self.assertEqual(f.scheduler.sampling_count(),1)

    async def test_unqualified_trials_keep_sampling_concurrency_bounded(self):
        f=Fixture()
        for target in ('a','b','nas'):
            route=f.route('us',target)
            f.primary(route,900);f.options[target]=[route]
            if target!='nas':
                trial=f.route('other',target)
                f.scheduler.trials[target]=f.binding(trial,samples=0)
                f.options[target].append(trial)
        f.options['nas'].append(f.route('shanghai','nas'))
        await f.step()
        self.assertFalse(f.opened)
        self.assertEqual(f.scheduler.sampling_count(),MAX_TRIALS)
        for _ in range(3): f.scheduler.trials['a'].session.latency.add(950,f.now)
        await f.step()
        self.assertEqual(len(f.opened),1)

    async def test_lan_first_hop_can_be_sampled_even_with_one_extra_hop(self):
        f=Fixture()
        original=f.route('us','ii',first_rtt=250)
        slower=f.route('other-us','ii',first_rtt=260)
        local=f.route('shanghai','nas','ii',first_rtt=8)
        f.primary(original,900);f.options['ii']=[original,slower,local]
        await f.step()
        self.assertEqual(f.opened,[local.path])
        standby=f.scheduler.trials['ii']
        # Three fresh samples qualify the trial, then three fresh comparisons
        # are still required before publishing the lower-cost route.
        for index in range(5):
            f.now+=1
            f.scheduler.active['ii'].session.latency.add(900,f.now)
            standby.session.latency.add(30,f.now)
            await f.step()
        self.assertEqual(f.scheduler.active['ii'].route.path,local.path)
        self.assertEqual(f.scheduler.reasons['ii'],'lower_cost')

    async def test_initial_connection_tries_near_first_hop_before_fewer_hops(self):
        f=Fixture()
        distant=f.route('us','ii',first_rtt=250)
        nearby=f.route('shanghai','nas','ii',first_rtt=8)
        f.options['ii']=[distant,nearby]
        await f.scheduler.establish(f.manager.pairs['ii'],background=True)
        self.assertEqual(f.opened,[nearby.path])

    async def test_reverse_session_is_reused_and_inbound_reply_drains(self):
        f=Fixture();route=f.route('shanghai','nas')
        old=f.primary(route,40,identity='z')
        old.session.handling.add('reply')
        shared=f.binding(route,40,identity='a',incoming=True)
        f.options['nas']=[route]
        await f.step()
        self.assertIs(f.scheduler.active['nas'].session,shared.session)
        self.assertIn('z',f.circuits)
        self.assertEqual(f.scheduler.counts['sessions_reused'],1)
        self.assertFalse(f.opened)
        old.session.handling.clear();await f.step()
        self.assertNotIn('z',f.circuits)

    async def test_existing_verified_route_is_not_opened_twice(self):
        f=Fixture();route=f.route('shanghai','nas')
        f.binding(route,40,incoming=True)
        await f.scheduler.open_trial(f.manager.pairs['nas'],route)
        self.assertFalse(f.opened)
        self.assertEqual(f.scheduler.counts['trial_sessions_reused'],1)

    async def test_duplicate_standby_does_not_invalidate_the_active_route(self):
        f=Fixture();route=f.route('shanghai','nas')
        primary=f.primary(route,40,identity='a')
        duplicate=f.binding(route,40,identity='z')
        f.scheduler.trials['nas']=duplicate;f.options['nas']=[route]
        await f.step()
        self.assertNotIn('z',f.circuits)
        self.assertIs(f.scheduler.connection_for('nas'),primary.session)

    async def test_idle_standby_is_reclaimed_while_console_is_open(self):
        f=Fixture();primary=f.route('shanghai','nas');standby=f.route('us','nas')
        f.primary(primary,20);f.scheduler.used.clear()
        old=f.binding(standby,900);old.circuit.created=0
        f.scheduler.trials['nas']=old;f.options['nas']=[primary,standby]
        await f.step()
        self.assertNotIn(old.circuit.identity,f.circuits)
        self.assertFalse(f.opened)
        self.assertEqual(f.scheduler.counts['standbys_reclaimed'],1)

    async def test_busy_candidate_backs_off_without_discarding_ticket(self):
        f=Fixture();route=f.route('shanghai','nas')
        f.relay.open_route=AsyncMock(side_effect=PeerError('BUSY','Peer is occupied'))
        delays=[]
        for _ in range(4):
            await f.scheduler.open_trial(f.manager.pairs['nas'],route)
            delay=f.scheduler.failed[f.scheduler.route_key(route)]-f.now
            delays.append(delay);f.now+=delay
        self.assertEqual(delays,[COOLDOWN,10,20,30])
        self.assertEqual(f.scheduler.path_errors['nas'],'trial_busy')

    async def test_idle_reaper_waits_for_pending_requests_handlers_and_writes(self):
        relay=self.relay();now=1000.
        circuit=Circuit('fixture',('company','target'),object(),None,None)
        circuit.ready.set();circuit.created=now-100;circuit.last_wire=now
        session=SimpleNamespace(last_business=now-61,closed=False,pending={},handling={'request'},write_bytes=0)
        circuit.session=session;relay.register(circuit)
        relay.reap_idle(now);self.assertIn('fixture',relay.circuits)
        session.handling.clear();session.write_bytes=100
        relay.reap_idle(now);self.assertIn('fixture',relay.circuits)
        session.write_bytes=0;session.pending['request']=('service.logs',None)
        relay.reap_idle(now);self.assertIn('fixture',relay.circuits)
        session.pending.clear();relay.reap_idle(now)
        self.assertNotIn('fixture',relay.circuits)
        self.assertEqual(relay.counts['idle_reclaimed'],1)

    async def test_reuse_is_rechecked_before_publishing_new_session(self):
        f=Fixture();route=f.route('shanghai','nas')
        old=f.primary(route,40,identity='z')
        shared=f.binding(route,40,identity='a',incoming=True)
        f.options['nas']=[route]
        async def changed(pair,binding,commit,check):
            shared.session.latency.sampled_at=f.now-60
            check();commit()
        f.scheduler.prepare=changed
        await f.step()
        self.assertIs(f.scheduler.active['nas'],old)
        self.assertIn('z',f.circuits)
        self.assertEqual(f.scheduler.counts['switches_deferred'],1)


if __name__=='__main__':
    unittest.main()
