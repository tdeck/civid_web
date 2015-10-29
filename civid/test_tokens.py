from tokens import Tokenizer, InvalidTokenError, InvalidCodeError
from freezegun import freeze_time
from pytest import raises

tokenizer = Tokenizer('sekrit')

def test_login_tokens():
    user = 'SomeUser__123456'

    token = None
    with freeze_time('2015-10-17 14:00:01'):
        token = tokenizer.create_login_token(user)

        assert tokenizer.validate_login_token(token) == user

    # After 1 minute, the token should still work
    with freeze_time('2015-10-17 14:01:01'):
        assert tokenizer.validate_login_token(token) == user

    # After 2 minutes, the token should be expired
    with freeze_time('2015-10-17 14:02:01'):
        with raises(InvalidTokenError):
            tokenizer.validate_login_token(token)

    with raises(InvalidTokenError):
        tokenizer.validate_login_token('')

    with raises(InvalidTokenError):
        tokenizer.validate_login_token('tooshort')

def test_identity_codes():
    user = 'SomeUser__123456'

    code = None
    with freeze_time('2015-10-17 14:00:00'):
        code = tokenizer.create_identity_code(user)

        assert tokenizer.validate_identity_code(code) == user

    # Check that the username doesn't obviously appear in the code
    # so people don't try to parse it out
    assert user not in code

    # After 29 seconds, the code should still work
    with freeze_time('2015-10-17 14:00:29'):
        assert tokenizer.validate_identity_code(code) == user

    # After 31 seconds, it should be expired
    with freeze_time('2015-10-17 18:00:31'):
        with raises(InvalidCodeError):
            tokenizer.validate_identity_code(code)

    with raises(InvalidCodeError):
        tokenizer.validate_identity_code('')
