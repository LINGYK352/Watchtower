"""漏洞点索引：会话内报送幂等之外，统一跨会话展示和首次发现真相源。"""
from sentinel_platform.contracts import Collections
from . import _finding_quality as quality

VERSION = 2


def point_key(row):
    target = str(row.get('target') or '')
    name = str(row.get('vuln_type') or row.get('name') or '')
    if not quality.endpoint(target)[0] or not name:
        return 'unclassified:' + str(row['_id'])
    return quality.identity('', target, name, row.get('parameter', ''), quality.request_method(row))


def index_one(repo, row):
    key = point_key(row)
    # 同时刻严格先到先得；不能用随机/哈希 ObjectId 大小打破平局，否则后来的记录会抢成首次。
    date = str(row.get('save_date') or row.get('time') or '9999-12-31 23:59:59')
    stamp = '{}|{:020d}'.format(date, int(row.get('observed_at_ns') or 0))
    first = {'first_time': stamp, 'first_id': str(row['_id']), 'first_seen_at': date}
    anchors = repo.collection(Collections.FINDING_IDENTITY)
    try:
        anchors.update_one({'_id': key}, {'$setOnInsert': first}, upsert=True)
    except Exception as exc:
        # 并发 upsert 可遇到 _id 冲突；重试已存在的同一个锚，不放行成多个首次。
        if 'duplicate' not in str(exc).lower() and 'e11000' not in str(exc).lower():
            raise
    anchors.update_one({'_id': key, 'first_time': {'$gt': stamp}}, {'$set': first})
    anchor=anchors.find_one({'_id':key}) or {}
    if anchor.get('first_id') and anchor['first_id']!=str(row['_id']):
        from bson import ObjectId
        owner=ObjectId(anchor['first_id']) if ObjectId.is_valid(anchor['first_id']) else anchor['first_id']
        alias=repo.collection(Collections.INTEL_FINDING).find_one({'_id':owner,'duplicate_of':str(row['_id'])})
        if alias:anchors.update_one({'_id':key,'first_id':anchor['first_id']},{'$set':{'first_id':str(row['_id'])}})
    repo.collection(Collections.INTEL_FINDING).update_one({'_id': row['_id']}, {'$set': {
        'point_key': key, 'point_index_version': VERSION}})
    row['point_key'] = key
    row['point_index_version'] = VERSION
    return key


def ensure_legacy_index(repo):
    """幂等补齐存量记录；不改评级、PoC、人工状态或历史，不靠进程缓存判断是否完成。"""
    collection = repo.collection(Collections.INTEL_FINDING)
    count = 0
    for row in collection.find({'source': 'ai', 'duplicate_of':None,'point_index_version': {'$ne': VERSION}}).sort([('save_date', 1), ('_id', 1)]):
        index_one(repo, row)
        count += 1
    return count


def annotate(repo, rows):
    keys = {row.get('point_key') for row in rows if row.get('point_key')}
    if not keys:
        return rows
    anchors = {row['_id']: row for row in
               repo.collection(Collections.FINDING_IDENTITY).find({'_id': {'$in': list(keys)}})}
    for row in rows:
        anchor = anchors.get(row.get('point_key'))
        if not anchor or not anchor.get('first_id'):
            row['first_seen'] = None
            continue
        owner = anchor['first_id']
        row['first_seen'] = str(row['_id']) == owner
        row['first_seen_at'] = anchor['first_seen_at']
        row['first_finding_id'] = owner
    return rows


def select_rows(collection, query, fetch_n, dedup):
    """先按漏洞点分组，再截取分页窗口；总数为完整筛选结果，不是当前页条数。"""
    if hasattr(collection, 'aggregate'):
        pipeline = [{'$match': query}, {'$sort': {'save_date': -1, '_id': -1}}]
        if dedup:
            pipeline += [{'$group': {'_id': '$point_key', 'row': {'$first': '$$ROOT'}, 'count': {'$sum': 1}}},
                         {'$replaceRoot': {'newRoot': {'$mergeObjects': ['$row', {'occurrence_count': '$count'}]}}},
                         {'$sort': {'save_date': -1, '_id': -1}}]
        pipeline.append({'$facet': {'items': [{'$limit': fetch_n}], 'total': [{'$count': 'count'}]}})
        result = list(collection.aggregate(pipeline, allowDiskUse=True))
        page = result[0] if result else {}
        total = (page.get('total') or [{}])[0].get('count', 0)
        return page.get('items', []), total
    # 非 Mongo 仓储的等价实现；生产路径使用上方原生聚合。
    rows = list(collection.find(query).sort([('save_date', -1), ('_id', -1)]))
    if dedup:
        selected = {}
        for raw in rows:
            key = raw.get('point_key') or point_key(raw)
            if key not in selected:
                selected[key] = {**raw, 'occurrence_count': 0}
            selected[key]['occurrence_count'] += 1
        rows = list(selected.values())
    return rows[:fetch_n], len(rows)


def statistics(collection, query):
    if hasattr(collection, 'aggregate'):
        result = list(collection.aggregate([
            {'$match': query}, {'$sort': {'save_date': -1, '_id': -1}},
            {'$group': {'_id': '$point_key', 'row': {'$first': '$$ROOT'}}},
            {'$replaceRoot': {'newRoot': '$row'}},
            {'$facet': {
                'verified': [{'$match': {'verified': True}}, {'$count': 'n'}],
                'leads': [{'$match': {'verified': {'$ne': True}}}, {'$count': 'n'}],
                'severity': [{'$match': {'verified': True}}, {'$group': {'_id': '$severity', 'n': {'$sum': 1}}}],
                'types': [{'$match': {'verified': True}}, {'$group': {'_id': '$vuln_type', 'n': {'$sum': 1}}}],
            }}], allowDiskUse=True))
        value = result[0] if result else {}
        return ((value.get('verified') or [{}])[0].get('n', 0),
                (value.get('leads') or [{}])[0].get('n', 0),
                {r['_id'] or 'unknown': r['n'] for r in value.get('severity', [])},
                {r['_id'] or 'unknown': r['n'] for r in value.get('types', [])})
    rows = list(collection.find(query).sort([('save_date', -1), ('_id', -1)]))
    seen, verified, leads, severities, types = set(), 0, 0, {}, {}
    for row in rows:
        key = row.get('point_key') or point_key(row)
        if key in seen: continue
        seen.add(key)
        if row.get('verified'):
            verified += 1
            severity, name = row.get('severity') or 'unknown', row.get('vuln_type') or 'unknown'
            severities[severity] = severities.get(severity, 0) + 1
            types[name] = types.get(name, 0) + 1
        else:
            leads += 1
    return verified, leads, severities, types
