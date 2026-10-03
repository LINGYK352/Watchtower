import unittest
from unittest.mock import patch
from sentinel_platform.modules.kernel.recon.tools import naabu
class NaabuPlatformTest(unittest.TestCase):
    def test_windows_default_uses_connect_without_requiring_driver(self):
        with patch.object(naabu.os,'name','nt'):args=naabu.Naabu().build_argv(ports='443')
        self.assertEqual(args[args.index('-s')+1],'c');self.assertEqual(args[args.index('-p')+1],'443')
    def test_linux_default_is_unchanged(self):
        with patch.object(naabu.os,'name','posix'):args=naabu.Naabu().build_argv()
        self.assertNotIn('-s',args)
if __name__=='__main__':unittest.main()
