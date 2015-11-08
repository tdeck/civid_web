from itsdangerous import TimestampSigner
from time import time
import base64
import hashlib
import string

LOGIN_WINDOW_S = 60
CODE_WINDOW_S = 30
SHORT_SIG_LENGTH = 18
MIN_USERNAME_LENGTH = 3

USERNAME_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
SHUFFLED_CHARS = 'NGthMiXu2xmnfzVROkEjvaUPYg1AqyZcbL7C_6WIJQoDeT85SHrKB40l3F9sdpw'
scrambler = string.maketrans(USERNAME_CHARS, SHUFFLED_CHARS)
unscrambler = string.maketrans(SHUFFLED_CHARS, USERNAME_CHARS)

class InvalidTokenError(Exception): pass
class InvalidCodeError(Exception): pass

def now_str():
    return '@' + str(int(time()) / LOGIN_WINDOW_S)

def last_period_str():
    return '@' + str(int(time()) / LOGIN_WINDOW_S - 1)

def scramble_username(username):
    """
    Encodes the username with a simple substitution cipher.

    >>> scramble_username('lgp30')
    'nXRlB'
    """
    return string.translate(str(username), scrambler)

def unscramble_username(ciphertext):
    """
    Returns the plaintext for a username scrambled with scramble_username.

    >>> unscramble_username('nXRlB')
    'lgp30'
    """
    return string.translate(ciphertext, unscrambler)

class Tokenizer(object):
    """
    A class for creating cryptographically signed tokens used by CivID.

    >>> tokenizer = Tokenizer('123')
    >>> lt = tokenizer.create_login_token('gatzy')
    >>> tokenizer.validate_login_token(lt)
    'gatzy'
    >>> ic = tokenizer.create_identity_code('ttk2')
    >>> tokenizer.validate_identity_code(ic)
    'ttk2'
    """
    def __init__(self, signing_key):
        self.key = signing_key
        self.signer = TimestampSigner(signing_key)

    def short_sig(self, string):
        """
        Returns a token computed from truncating the hash of the given
        string with the signing key.
        """
        return base64.urlsafe_b64encode(
            hashlib.sha256(self.key + string).digest()
        )[:SHORT_SIG_LENGTH]

    def create_login_token(self, username):
        """
        Creates a login token of the form "signatureUsername".
        This token is bound to a UNIX timestamp divided by LOGIN_WINDOW_S,
        but it is not stored within the token in order to limit its length.
        """
        return self.short_sig(username + now_str()) + username

    def validate_login_token(self, token):
        if len(token) < SHORT_SIG_LENGTH + MIN_USERNAME_LENGTH:
            raise InvalidTokenError("Malformed token")

        signature = token[0:SHORT_SIG_LENGTH]
        user = token[SHORT_SIG_LENGTH:]
        
        if (
            signature != self.short_sig(user + now_str()) and 
            signature != self.short_sig(user + last_period_str())
        ):
            raise InvalidTokenError("Login link invalid or expired")

        return user

    def create_identity_code(self, username):
        # Identity codes contain this silly "scrambled" version of the username
        # to discourage naive implementations from parsing it out of the code
        # without making a request to validate it against the CivID server.
        return self.signer.sign(scramble_username(username))

    def validate_identity_code(self, code):
        try:
            return unscramble_username(self.signer.unsign(code, max_age=CODE_WINDOW_S))
        except:
            raise InvalidCodeError()
