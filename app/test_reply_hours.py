from datetime import datetime, timedelta, timezone
import unittest

from reply_hours import replies_allowed


class ReplyHoursTests(unittest.TestCase):
    def test_beijing_midnight_to_seven_is_silent(self):
        zone = timezone(timedelta(hours=8))
        for hour, minute in ((0, 0), (1, 8), (6, 59)):
            self.assertFalse(replies_allowed(datetime(2026, 10, 19, hour, minute, tzinfo=zone)))
        for hour, minute in ((7, 0), (23, 59)):
            self.assertTrue(replies_allowed(datetime(2026, 10, 19, hour, minute, tzinfo=zone)))

    def test_utc_input_is_converted_to_beijing(self):
        self.assertFalse(replies_allowed(datetime(2026, 10, 18, 16, tzinfo=timezone.utc)))
        self.assertTrue(replies_allowed(datetime(2026, 10, 18, 23, tzinfo=timezone.utc)))


if __name__ == '__main__':
    unittest.main()
