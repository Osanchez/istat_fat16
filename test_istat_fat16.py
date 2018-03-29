import unittest

import istat_fat16
import tsk_helper


class TestIstatFat16(unittest.TestCase):
    def testAdams5(self):
        with open('adams.dd.5.out') as f:
            expected = tsk_helper.strip_all(tsk_helper.get_fsstat_output(f))
        with open('adams.dd', 'rb') as f:
            actual = tsk_helper.strip_all(istat_fat16.istat_fat16(f, 5))

        self.assertEqual(expected, actual)

    def testAdams7(self):
        with open('adams.dd.7.out') as f:
            expected = tsk_helper.strip_all(tsk_helper.get_fsstat_output(f))
        with open('adams.dd', 'rb') as f:
            actual = tsk_helper.strip_all(istat_fat16.istat_fat16(f, 7))

        self.assertEqual(expected, actual)

    def testAdams549(self):
        # note: 590F-only
        with open('adams.dd.549.out') as f:
            expected = tsk_helper.strip_all(tsk_helper.get_fsstat_output(f))
        with open('adams.dd', 'rb') as f:
            actual = tsk_helper.strip_all(istat_fat16.istat_fat16(f, 549))

        self.assertEqual(expected, actual)

if __name__ == '__main__':
    unittest.main()
