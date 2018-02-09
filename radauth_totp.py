import os
import sys
import subprocess

import time
import datetime

import hmac
import base64
import hashlib

#
# https://github.com/pyotp/pyotp
# https://pyotp.readthedocs.io/en/latest/
#

USING_PYTHON2 = True if sys.version_info < (3, 0) else False

if USING_PYTHON2:
    str = unicode  # noqa
else:
    str = str

class OTP(object):
    """
    Base class for OTP handlers.
    """
    def __init__(self, s, digits=6, digest=hashlib.sha1):
        """
        :param s: secret in base32 format
        :type s: str
        :param digits: number of integers in the OTP. Some apps expect this to be 6 digits, others support more.
        :type digits: int
        :param digest: digest function to use in the HMAC (expected to be sha1)
        :type digest: callable
        """
        self.digits = digits
        self.digest = digest
        self.secret = s

    def generate_otp(self, input):
        """
        :param input: the HMAC counter value to use as the OTP input.
            Usually either the counter, or the computed integer based on the Unix timestamp
        :type input: int
        """
        if input < 0:
            raise ValueError('input must be positive integer')
        hasher = hmac.new(self.byte_secret(), self.int_to_bytestring(input), self.digest)
        hmac_hash = bytearray(hasher.digest())
        offset = hmac_hash[-1] & 0xf
        code = ((hmac_hash[offset] & 0x7f) << 24 |
                (hmac_hash[offset + 1] & 0xff) << 16 |
                (hmac_hash[offset + 2] & 0xff) << 8 |
                (hmac_hash[offset + 3] & 0xff))
        str_code = str(code % 10 ** self.digits)
        while len(str_code) < self.digits:
            str_code = '0' + str_code

        return str_code

    def byte_secret(self):
        missing_padding = 16 % len(self.secret) % 8
        if missing_padding != 0:
            self.secret += '=' * (8 - missing_padding)
        return base64.b32decode(self.secret, casefold=True)

    @staticmethod
    def int_to_bytestring(i, padding=8):
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = bytearray()
        while i != 0:
            result.append(i & 0xFF)
            i >>= 8
        # It's necessary to convert the final result from bytearray to bytes
        # because the hmac functions in python 2.6 and 3.3 don't work with
        # bytearray
        return bytes(bytearray(reversed(result)).rjust(padding, b'\0'))

class TOTP(OTP):
    """
    Handler for time-based OTP counters.
    """
    def __init__(self, *args, **kwargs):
        """
        :param interval: the time interval in seconds
            for OTP. This defaults to 30.
        :type interval: int
        """
        self.interval = kwargs.pop('interval', 30)
        super(TOTP, self).__init__(*args, **kwargs)

    def at(self, for_time, counter_offset=0):
        """
        Accepts either a Unix timestamp integer or a datetime object.
        :param for_time: the time to generate an OTP for
        :type for_time: int or datetime
        :param counter_offset: the amount of ticks to add to the time counter
        :returns: OTP value
        :rtype: str
        """
        if not isinstance(for_time, datetime.datetime):
            for_time = datetime.datetime.fromtimestamp(int(for_time))
        return self.generate_otp(self.timecode(for_time) + counter_offset)

    def timecode(self, for_time):
        i = time.mktime(for_time.timetuple())
        return int(i / self.interval)
