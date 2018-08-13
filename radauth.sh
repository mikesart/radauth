#!/usr/bin/env python

import os
import re
import sys
import time
import datetime
import logging
import logging.handlers

sys.path.append(os.getcwd())

import utils
import mschap
import mppe
import radauth_totp

LOG_FILENAME = os.path.dirname(os.path.realpath(__file__)) + '/radauth.log'
PASSWDS_FILENAME = os.path.dirname(os.path.realpath(__file__)) + '/radauthpw.txt'

# cat /usr/syno/etc/preference/mikesart/google_authenticator
#  P34LSF5MU24VNI2B
#  ...
debug_google_auth_file = '' # "./google_authenticator"

# https://networkradius.com/doc/3.0.9/raddb/mods-available/exec.html
RLM_MODULE_OK = 0               # the module succeeded
RLM_MODULE_REJECT = 1           # the module rejected the user
RLM_MODULE_INVALID = 5          # the user's configuration entry was invalid
RLM_MODULE_USER_NOT_FOUND = 7   # the user was not found

logger = logging.getLogger('radauth')
loghandler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=64000, backupCount=10)
logformatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
loghandler.setFormatter(logformatter)
logger.addHandler(loghandler)

# DEBUG, INFO, WARNING, ERROR and CRITICAL
logger.setLevel(logging.INFO)
# logger.debug('this is a debug')
# logger.info('this is an info')
# logger.warning('this is a warning')
# logger.error('this is an error')
# logger.critical('this is a critical')

def printret(s):
    logger.info("PRINTRET: '%s'" % s)
    print(s)

# list installed python modules
# help("modules")

class Input:
    def __init__(self):
        logger.info("---------------------")
        logger.info("os.environ: %s" % vars(os.environ))

        self.is_valid = False
        self.etc_passwd = ''
        self.user_password = ''
        self.ms_chap2_response = ''
        self.ms_chap_challenge = ''
        self.codes = []

        self.name = os.environ.get('USER_NAME', 'user').strip('"')

        # unencrypted password (pap)
        if 'USER_PASSWORD' in os.environ:
            self.user_password = os.environ.get('USER_PASSWORD', '').strip('"')

        # ms_chapv2
        if 'MS_CHAP2_RESPONSE' in os.environ:
            self.ms_chap2_response = os.environ.get('MS_CHAP2_RESPONSE', '') # mschapv2_response
            self.ms_chap_challenge = os.environ.get('MS_CHAP_CHALLENGE', '') # auth_challenge

            self.ms_chap2_response = re.sub('^0x', '', self.ms_chap2_response)
            self.ms_chap_challenge = re.sub('^0x', '', self.ms_chap_challenge)

        # Read radauthpw.txt file for username -> password values
        user_passwds = {}
        with open(PASSWDS_FILENAME, 'r') as f:
            s = f.read()
            user_passwds = eval( s )
        self.etc_passwd = user_passwds.get( self.name, 'nopassword' )

        # Get full path to user's google_authenticator file
        if not debug_google_auth_file:
            self.fname = "/usr/syno/etc/preference/" + self.name + "/google_authenticator"
        else:
            self.fname = debug_google_auth_file

        self.fname_exists = os.path.isfile(self.fname)
        self.fname_isreadable = os.access(self.fname, os.R_OK)

        self.t0 = datetime.datetime.now()

        if self.fname_exists and self.fname_isreadable:
            with open(self.fname, 'r') as f:
                self.google_secret = f.readline().rstrip()

                try:
                    self.totp = radauth_totp.TOTP(self.google_secret)

                    for i in range(-3, 4):
                        self.codes.append(self.totp.at(self.t0, i))

                    self.is_valid = True
                except:
                    self.exc_info = sys.exc_info()[0]

        # Check if we have a debugging environ var forcing our password
        # Also append a blank code if so
        if 'RADAUTH_ETC_PASSWD' in os.environ:
            self.etc_passwd = os.environ.get('RADAUTH_ETC_PASSWD')
            self.codes.append('')

"""
  ## debug chapv2 test data ##

  https://tools.ietf.org/html/rfc2759#section-9.2

  0-to-256-char UserName:           55 73 65 72 (User)
  0-to-256-unicode-char Password:   63 00 6C 00 69 00 65 00 6E 00 74 00 50 00 61 00 73 00 73 00 (clientPass)
  16-octet AuthenticatorChallenge:  5B 5D 7C 7D 7B 3F 2F 3E 3C 2C 60 21 32 26 26 28
  16-octet PeerChallenge:           21 40 23 24 25 5E 26 2A 28 29 5F 2B 3A 33 7C 7E
  8-octet Challenge:                D0 2E 43 86 BC E9 12 26
  16-octet PasswordHash:            44 EB BA 8D 53 12 B8 D6 11 47 44 11 F5 69 89 AE
  24 octet NT-Response:             82 30 9E CD 8D 70 8B 5E A0 8F AA 39 81 CD 83 54 42 33 11 4A 3D 85 D6 DF
  16-octet PasswordHashHash:        41 C0 0C 58 4B D2 D9 1C 40 17 A2 A1 2F A5 9F 3F
  42-octet AuthenticatorResponse:   'S=407A5589115FD0D6209F510FE9C04566932CDA56'

  USER_NAME="User" \
    RADAUTH_ETC_PASSWD="clientPass" \
    MS_CHAP_CHALLENGE="0x5B5D7C7D7B3F2F3E3C2C602132262628" \
    MS_CHAP2_RESPONSE="0xyyyy21402324255E262A28295F2B3A337C7Exxxxxxxxxxxxxxxx82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF" \
    ./radauth.sh
"""
class Chap:
    peer_challenge = ''
    peer_nt_response = ''
    mschapv1_challenge = ''
    nt_response = ''

def handle_mschapv2(input):
    chap = Chap()

    logger.info("handle_mschapv2: %s" % vars(input))

    # 16-octet AuthenticatorChallenge
    auth_challenge_bin = input.ms_chap_challenge.decode("hex")

    # get 16-octect PeerChallenge from mschapv2_response in hex and bin
    chap.peer_challenge = input.ms_chap2_response[4:36].upper()
    peer_challenge_bin = chap.peer_challenge.decode("hex")

    # get 24 octect peer_nt_response from mschapv2_response in hex and bin
    chap.peer_nt_response = input.ms_chap2_response[52:100].upper()
    peer_nt_response_bin = chap.peer_nt_response.decode("hex")

    # generate mschapv1 challenge from auth_challenge and peer_challenge
    mschapv1_challenge_bin = mschap.challenge_hash(peer_challenge_bin, auth_challenge_bin, input.name)
    chap.mschapv1_challenge = mschapv1_challenge_bin.encode("hex").upper()

    logger.info("chap vars: %s" % vars(chap))

    for code in input.codes:
        password = input.etc_passwd + code

        nt_response_bin = mschap.generate_nt_response_mschap2(auth_challenge_bin, peer_challenge_bin, input.name, password)

        # log password with NT-Response
        nt_response = nt_response_bin.encode("hex").upper()
        logger.info("password:%s nt_response:%s" % (password, nt_response))

        if peer_nt_response_bin == nt_response_bin:
            authenticator_response = mschap.generate_authenticator_response(nt_response_bin, peer_challenge_bin, auth_challenge_bin, input.name, password)

            # Success packet
            # http://tools.ietf.org/html/rfc2759#section-5
            # https://www.ietf.org/rfc/rfc1994.txt
            #  If the Value received in a Response is equal to the expected
            #  value, then the implementation MUST transmit a CHAP packet with
            #  the Code field set to 3 (Success).
            resp = "3" + authenticator_response;
            printret('Reply-Message := "Authentication successful",')
            printret('MS-CHAP2-Success := "0x%s"' % resp.encode("hex"))
            return RLM_MODULE_OK

    # Failure Packet
    # http://tools.ietf.org/html/rfc2759#section-6
    #   691 ERROR_AUTHENTICATION_FAILURE
    #   R=0, no retry
    printret('Reply-Message := "Authentication failed",')
    printret('MS-CHAP-Error := "E=691 R=0"')
    return RLM_MODULE_REJECT

"""
  USER_NAME=mikesart \
    USER_PASSWORD=password727226 \
    RADAUTH_ETC_PASSWD=password \
    ./radauth.sh
"""
def handle_pap(input):
    # assume user password is in password123456 format...
    input.pap_otp = input.user_password[-6:]      # 123456
    input.pap_password = input.user_password[:-6] # password

    logger.info("handle_pap: %s" % vars(input))

    if input.pap_password == input.etc_passwd:
        for code in input.codes:
            if code == input.pap_otp:
                printret('Reply-Message := "PAP Authentication successful"')
                return RLM_MODULE_OK

    printret('Reply-Message := "PAP Authentication failed"')
    return RLM_MODULE_REJECT

if __name__ == "__main__":
    input = Input()

    if not input.is_valid:
        logger.error("invalid input: %s" % vars(input))
        printret('Reply-Message := "Authentication failed: Unrecognized input"')
        ret = RLM_MODULE_INVALID
    elif input.ms_chap2_response and input.ms_chap_challenge:
        ret = handle_mschapv2(input)
    elif input.user_password:
        ret = handle_pap(input)
    else:
        logger.error("unrecognized input: %s" % vars(input))
        printret('Reply-Message := "Authentication failed: Unrecognized protocol"')
        ret = RLM_MODULE_INVALID

    exit(ret)
