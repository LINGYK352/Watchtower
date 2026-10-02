import unittest
from unittest import mock
from sentinel_platform.modules.kernel import _celery_adapter as ca, orchestration as orch

class TaskEnvelopeTest(unittest.TestCase):
    def setUp(self):
        self.missing = object()
        self.executor = orch._EXECUTOR
        self.saved={k:orch.__dict__.get(k, self.missing) for k in ['_celery_delay','_celery_session_delay','_celery_console_delay']}
        self.sender=mock.Mock();self.patch=mock.patch.object(ca,'_RUN_TASK',self.sender);self.patch.start()
        ca.install_celery_executor()
    def tearDown(self):
        self.patch.stop();orch.set_executor(self.executor)
        for k,v in self.saved.items():
            if v is self.missing:orch.__dict__.pop(k,None)
            else:setattr(orch,k,v)
    def doc_repo(self,doc):
        repo=mock.Mock();repo.collection.return_value.find_one.return_value=doc;return repo
    def test_small_options_do_not_add_database_reads(self):
        options={'dns_query':True}
        with mock.patch.object(orch,'get_repo',side_effect=AssertionError('small message must remain inline')):
            orch._celery_delay('t1','domain',options)
        self.sender.delay.assert_called_once_with('t1','domain',options)
    def test_large_persisted_options_use_legacy_compatible_reference(self):
        options={'targets':['site-'+str(i) for i in range(20000)]};doc={'task_type':'domain','options':options}
        with mock.patch.object(orch,'get_repo',return_value=self.doc_repo(doc)):
            orch._celery_delay('t1','domain',options)
        self.sender.delay.assert_called_once_with('t1','domain',None)
        self.assertEqual(len(options['targets']),20000)
    def test_unpersisted_override_and_type_mismatch_stay_inline(self):
        options={'body':'x'*50000}
        for doc in [None,{'task_type':'domain','options':{}},{'task_type':'ip','options':options}]:
            self.sender.reset_mock()
            with mock.patch.object(orch,'get_repo',return_value=self.doc_repo(doc)):
                orch._celery_delay('t1','domain',options)
            self.sender.delay.assert_called_once_with('t1','domain',options)
    def test_database_unavailable_retains_original_arguments(self):
        options={'body':'x'*50000}
        with mock.patch.object(orch,'get_repo',side_effect=RuntimeError('offline')):
            orch._celery_delay('t1','domain',options)
        self.sender.delay.assert_called_once_with('t1','domain',options)
    def test_missing_worker_parameters_requeue_without_running_handler(self):
        result=mock.Mock(modified_count=1);coll=mock.Mock()
        coll.find_one.side_effect=RuntimeError('temporary outage');coll.update_one.return_value=result
        repo=mock.Mock();repo.collection.return_value=coll
        handler=mock.Mock()
        with mock.patch.object(orch,'get_repo',return_value=repo),mock.patch.object(orch,'get_handler',return_value=handler):
            outcome=orch.run_task('t1','domain',None)
        self.assertEqual(outcome['result'],'waiting');handler.assert_not_called()
        self.assertEqual(coll.update_one.call_args.args[0]['status'],orch.S_QUEUED)
    def test_message_size_estimator_is_not_a_target_limit(self):
        self.assertFalse(ca._large_task_options({'flag':True}))
        self.assertTrue(ca._large_task_options({'targets':['x']*50000}))

    def test_size_probe_does_not_copy_or_walk_entire_container(self):
        class BoundedList(list):
            def __iter__(self):
                for i, value in enumerate(super().__iter__()):
                    if i >= 256:
                        raise AssertionError('size hint must have bounded work')
                    yield value
        targets = BoundedList([True] * 1000)
        self.assertTrue(ca._large_task_options({'targets': targets}))
        self.assertEqual(len(targets), 1000)

    def test_reference_lookup_requires_queued_task(self):
        repo = self.doc_repo(None)
        with mock.patch.object(orch, 'get_repo', return_value=repo):
            orch._celery_delay('t1', 'domain', {'body': 'x' * 50000})
        query = repo.collection.return_value.find_one.call_args.args[0]
        self.assertEqual(query['status'], orch.S_QUEUED)

    def test_explicit_reference_preserves_three_argument_protocol(self):
        with mock.patch.object(orch, 'get_repo', side_effect=AssertionError('no producer read')):
            orch._celery_delay('t1', 'domain', None)
        self.sender.delay.assert_called_once_with('t1', 'domain', None)

    def test_worker_hydrates_complete_options_and_deduplicates(self):
        from .test_orchestration_phase2 import _Repo
        repo = _Repo()
        options = {'targets': ['target-' + str(i) for i in range(20000)]}
        repo.collection('task').insert_one({'_id': 't1', 'status': orch.S_QUEUED,
                                           'type': 'domain', 'options': options})
        seen = []
        def handler(task_id, ctx):
            seen.append(ctx.options)
        with mock.patch.object(orch, 'get_repo', return_value=repo), \
             mock.patch.object(orch, 'get_handler', return_value=handler), \
             mock.patch.object(orch, '_post_scan'):
            self.assertEqual(orch.run_task('t1', 'domain', None)['result'], 'done')
            self.assertEqual(orch.run_task('t1', 'domain', None)['result'], 'skipped_duplicate')
        self.assertEqual(seen, [options])

    def test_parameter_read_failure_can_resume_and_never_revives_stopped_task(self):
        from .test_orchestration_phase2 import _Repo
        for status in [orch.S_QUEUED, orch.S_STOP, orch.S_RUNNING]:
            repo = _Repo()
            coll = repo.collection('task')
            coll.insert_one({'_id': 't1', 'status': status, 'type': 'domain', 'options': {'flag': True}})
            original_read = coll.find_one
            failed = False
            def fail_once(*args, **kwargs):
                nonlocal failed
                if not failed:
                    failed = True
                    raise RuntimeError('temporary outage')
                return original_read(*args, **kwargs)
            handler = mock.Mock()
            with mock.patch.object(orch, 'get_repo', return_value=repo), \
                 mock.patch.object(coll, 'find_one', side_effect=fail_once), \
                 mock.patch.object(orch, 'get_handler', return_value=handler), \
                 mock.patch.object(orch, '_post_scan'):
                self.assertEqual(orch.run_task('t1', 'domain', None)['result'], 'waiting')
                handler.assert_not_called()
                expected = orch.S_WAITING if status == orch.S_QUEUED else status
                self.assertEqual(original_read({'_id': 't1'})['status'], expected)
                outcome = orch.run_task('t1', 'domain', None)
                if status == orch.S_QUEUED:
                    self.assertEqual(outcome['result'], 'done')
                    handler.assert_called_once()
                else:
                    handler.assert_not_called()

if __name__=='__main__':unittest.main()
