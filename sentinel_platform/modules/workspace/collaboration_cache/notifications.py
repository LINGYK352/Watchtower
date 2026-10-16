"""Durable, per-room read positions; receipt/download does not mean user has read."""
import hashlib
import secrets
import threading
import time
from datetime import datetime, timezone
from pymongo import ReturnDocument
from .policy import CacheError, identifier


class Notifications:
    def __init__(self, cache):
        self.cache = cache
        self.service, self.clock = cache.collaboration, cache.clock
        self.rows = cache.repo.collection('collaboration_read_cursors')
        self.rows.create_index([('owner', 1), ('group_id', 1), ('kind', 1)])
        self.rows.create_index('expires', expireAfterSeconds=0)

    @staticmethod
    def key(owner, gid='', room=''):
        return hashlib.sha256((owner + ':' + gid + ':' + room).encode()).hexdigest()

    def groups(self, user):
        host = [(r['_id'], r['_id']) for r in self.service.groups.find(
            {'owner': user['username'], 'enabled': True, 'deleted_at': {'$exists': False}}).limit(100)]
        links = [(r['group_id'], r['_id']) for r in self.service.links.find({'owner': user['username'],
            'state': 'approved', 'deleted_at': {'$exists': False}, 'expires_at': {'$gt': self.clock()}}).limit(100)]
        return dict(host + links)

    def revision(self, user, gid):
        row = self.cache.repo.collection('collaboration_rooms').find_one(
            {'_id': 'delivery:' + hashlib.sha256((user['username'] + ':' + gid).encode()).hexdigest()}) or {}
        return int(row.get('revision') or 0)

    def watch(self, user):
        owner = user['username']; now = self.clock()
        self.rows.update_one({'_id': 'watch:' + self.key(owner)}, {'$set': {'owner': owner, 'kind': 'watch',
            'watched_at': now, 'expires': datetime.fromtimestamp(now + 120, timezone.utc)}}, upsert=True)
        for gid in self.groups(user):
            self.rows.update_one({'_id': 'baseline:' + self.key(owner, gid)}, {'$setOnInsert': {
                'owner': owner, 'group_id': gid, 'kind': 'baseline', 'cursor': self.revision(user, gid)}}, upsert=True)

    def summary(self, user):
        result, rooms = {}, {}
        owner = user['username']
        for gid, mid in self.groups(user).items():
            base = self.rows.find_one({'_id': 'baseline:' + self.key(owner, gid)}) or {}
            floor = int(base.get('cursor') or 0)
            positions = list(self.rows.find({'owner': owner, 'group_id': gid, 'kind': 'room'}))
            read = [{'audience': row['audience'], 'sequence': {'$lte': row['cursor']},
                     **({'participants': row['participants']} if row['audience'] == 'direct' else {})}
                    for row in positions]
            query = {'owner': owner, 'group_id': gid, 'sequence': {'$gt': floor}, 'sender': {'$exists': True, '$ne': mid}}
            if read:
                query['$nor'] = read
            grouped = self.cache.received.aggregate([{'$match': query}, {'$group': {
                '_id': {'audience': '$audience', 'participants': '$participants'}, 'count': {'$sum': 1}}}])
            room_counts = {}
            for row in grouped:
                scope = row['_id']; audience = scope.get('audience')
                if audience == 'group':
                    room = 'group'
                elif audience == 'direct' and mid in scope.get('participants', []):
                    room = next((p for p in scope['participants'] if p != mid), '')
                else:
                    continue
                if room:
                    room_counts[room] = row['count']
            rooms[gid] = room_counts; result[gid] = sum(room_counts.values())
        return {'unread_total': sum(result.values()), 'unread_groups': result, 'unread_rooms': rooms}

    def read(self, gid, user, body):
        gid = identifier(gid); access = self.service._access(gid, user); mid = access['member_id']
        audience, peer = body.get('audience', 'group'), body.get('peer_id', '')
        if audience not in ('group', 'direct') or audience == 'group' and peer:
            raise CacheError('工作区范围无效 / Invalid workspace scope')
        participants = []
        if audience == 'direct':
            identifier(peer)
            if peer == mid:
                raise CacheError('单点工作区成员无效 / Invalid direct workspace member')
            participants = sorted((mid, peer))
        cursor = body.get('cursor')
        if isinstance(cursor, bool) or not isinstance(cursor, int) or not 0 <= cursor <= self.revision(user, gid):
            raise CacheError('已读游标无效 / Invalid read position')
        room = peer if audience == 'direct' else 'group'
        key = 'room:' + self.key(user['username'], gid, room)
        self.rows.update_one({'_id': key}, {'$max': {'cursor': cursor}, '$set': {
            'owner': user['username'], 'group_id': gid, 'kind': 'room', 'audience': audience,
            'participants': participants, 'read_at': self.clock()}}, upsert=True)
        return self.summary(user)

    def start(self):
        threading.Thread(target=self.run, daemon=True, name='watchtower-team-unread').start()

    def run(self):
        while True:
            try:
                self.tick()
            except Exception:
                pass
            time.sleep(2)

    def tick(self):
        from . import leave_notices
        leave_notices.flush(self.cache)
        now = self.clock()
        for watch in self.rows.find({'kind': 'watch', 'watched_at': {'$gt': now - 60},
                                    'next_at': {'$not': {'$gt': now}}}).limit(2):
            token = secrets.token_hex(16)
            held = self.rows.find_one_and_update({'_id': watch['_id'], '$or': [
                {'lease_until': {'$exists': False}}, {'lease_until': {'$lte': now}}]},
                {'$set': {'lease_until': now + 90, 'lease_owner': token, 'next_at': now + 6}},
                return_document=ReturnDocument.AFTER)
            if not held:
                continue
            user = {'username': watch['owner']}
            try:
                from sentinel_platform.contracts import Collections
                account = self.cache.repo.collection(Collections.USER).find_one({'username': watch['owner']})
                if not account or account.get('disabled'):
                    continue
                candidates = []
                for collection, query in ((self.service.groups, {'owner': watch['owner'], 'enabled': True}),
                        (self.service.links, {'owner': watch['owner'], 'state': 'approved', 'expires_at': {'$gt': now}, 'deleted_at': {'$exists': False}})):
                    row = collection.find_one_and_update(dict(query, notification_next={'$not': {'$gt': now}}),
                        {'$set': {'notification_next': now + 12}}, sort=[('notification_next', 1), ('created_at', 1)],
                        return_document=ReturnDocument.AFTER)
                    if row:
                        candidates.append(row.get('group_id') or row['_id'])
                for gid in candidates:
                    try:
                        self.cache.workspace(gid, user)
                        self.cache.heartbeat(gid, user)
                        self.cache.incoming(gid, user)
                    except Exception:
                        pass  # Unreachable workspace does not block notices in another workspace.
            finally:
                self.rows.update_one({'_id': watch['_id'], 'lease_owner': token},
                    {'$unset': {'lease_until': '', 'lease_owner': ''}})
