"""Stable identities for builtin configuration, independent of runtime modules."""
BUILTIN_PROMPT_SCENES = ('pentest_exec_detect','pentest_exec_conservative','pentest_exec','pentest_exec_redteam','code_audit','guard','guard_conservative','guard_detect','guard_redteam','observer','template_learn')
BUILTIN_REPORT_IDS = ('builtin_session_v1','builtin_task_v1','builtin_finding_v1')

def overwrite_only(collection, doc):
    # Task stages are one coherent configuration set, including custom stages.
    return (collection=='ai_prompt' or doc.get('builtin') is True or doc.get('is_builtin') is True
            or (collection=='report_template' and doc.get('_id') in BUILTIN_REPORT_IDS))
