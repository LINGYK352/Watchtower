"""Archive duplicated builtin stages and enforce a shared Mongo identity."""
from sentinel_platform.contracts.configuration import BUILTIN_PROMPT_SCENES

def reconcile_builtin_stages(repo):
    coll=repo.collection('ai_prompt');archive=repo.collection('ai_prompt_duplicate_archive');removed=0
    for scene in BUILTIN_PROMPT_SCENES:
        rows=list(coll.find({'scene':scene}))
        if not rows:continue
        # Preserve the same enabled row that the current engine find_one uses;
        # do not replace local edited text with an older imported ObjectId.
        keeper=next((row for row in rows if row.get('enabled') is True),rows[0])
        for row in rows:
            if row['_id']==keeper['_id']:continue
            archive.update_one({'_id':row['_id']},{'$setOnInsert':{'record':row,'retained_id':keeper['_id'],'reason':'duplicate_builtin_scene_135'}},upsert=True)
            if not coll.find_one({'_id':keeper['_id'],'scene':scene},{'_id':1}):break
            # Concurrent edits must match the archived value before deletion.
            removed+=coll.delete_one(row).deleted_count
        coll.update_one({'_id':keeper['_id'],'scene':scene},{'$set':{'builtin':True}})
    coll.create_index([('scene',1)],name='builtin_scene_unique',unique=True,partialFilterExpression={'builtin':True})
    return removed
