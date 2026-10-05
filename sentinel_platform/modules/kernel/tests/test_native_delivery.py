import unittest
from unittest.mock import patch
from sentinel_platform.modules.kernel import orchestration as o
class DeliveryTest(unittest.TestCase):
 def tearDown(self):o.set_delivery(None)
 def test_native_failure_rolls_back_claim_and_never_runs_inline(self):
  def fail(*args,**kwargs):raise RuntimeError('database unavailable')
  o.set_delivery(fail)
  with patch.object(o,'_read_status',return_value='waiting'),patch.object(o,'_claim_task',return_value=True),patch.object(o,'_rollback_task_claim') as rollback,patch.object(o,'_EXECUTOR') as inline:
   self.assertFalse(o.submit_task('owned-qa')['submitted']);rollback.assert_called_once();inline.assert_not_called()
 def test_native_keeps_explicit_options_and_task_type(self):
  captured=[];o.set_delivery(lambda kind,identifier,**kw:captured.append((kind,identifier,kw)) or 'job')
  with patch.object(o,'_read_status',return_value='waiting'),patch.object(o,'_claim_task',return_value=True):
   self.assertTrue(o.submit_task('owned-qa',{'type':'scan','options':{'target':'localhost'}})['submitted'])
  self.assertEqual(captured,[('task','owned-qa',{'task_type':'scan','options':{'target':'localhost'}})])
 def test_stopped_task_is_not_delivered(self):
  calls=[];o.set_delivery(lambda *args,**kwargs:calls.append(args))
  with patch.object(o,'_read_status',return_value='stop'),patch.object(o,'_claim_task') as claim:self.assertFalse(o.submit_task('owned-qa')['submitted']);claim.assert_not_called()
  self.assertEqual(calls,[])
