from freezegun import freeze_time
import os
import flask
import json

# These need to be configured before we import the app, or it'll error out
os.environ['SECRET_KEY'] = 'testkey'
os.environ['SIGNING_KEY'] = 'testkey'

import civid
app = civid.app

class TestHomepage:
    def test_homepage(self):
        with app.test_client() as tc:
            res = tc.get('/')
            assert res.status_code == 200
            # TODO

class TestLogin:
    @freeze_time('2015-09-30 00:00')
    def test_valid_token(self):
        with app.test_client() as tc:
            res = tc.get('/in/Vnthii-2D3jPp-Ownf0ptixs', follow_redirects=True)
            assert res.status_code == 200

            assert flask.session['username'] == '0ptixs'

    @freeze_time('2015-09-30 00:02')
    def test_expired_token(self):
        with app.test_client() as tc:
            res = tc.get('/in/Vnthii-2D3jPp-Ownf0ptixs', follow_redirects=True)
            assert res.status_code == 401

            assert 'username' not in flask.session

    def test_invalid_token(self):
        with app.test_client() as tc:
            res = tc.get('/in/abcdefg', follow_redirects=True)
            assert res.status_code == 401

class TestLogout:
    def test_with_session(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'foofed'

            res = tc.get('/out', follow_redirects=True)
            assert res.status_code == 200

            assert 'username' not in flask.session

    def test_without_session(self):
        with app.test_client() as tc:
            res = tc.get('/out', follow_redirects=True)
            assert res.status_code == 200

class TestGetAuthorize:
    def test_missing_redirect_uri(self):
        with app.test_client() as tc:
            res = tc.get('/authorize')
            assert res.status_code == 400

    def test_invalid_redirect_uris(self):
        with app.test_client() as tc:
            res = tc.get('/authorize?redirect_uri=gopher://localhost')
            assert res.status_code == 400

    def test_without_session(self):
        with app.test_client() as tc:
            res = tc.get('/authorize?redirect_uri=http://localhost')
            assert res.status_code == 200
            assert 'You are not logged in' in res.data
            assert 'Identify' not in res.data

    def test_with_session(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'karst1'

            res = tc.get('/authorize?redirect_uri=http%3A%2F%2Fcivballroom.io%2Fabc')
            assert res.status_code == 200
            assert 'The application at <strong>civballroom.io</strong>' in res.data
            assert 'username <strong>karst1</strong>' in res.data
            assert 'Identify' in res.data
            assert 'Decline' in res.data
            assert 'csrf_token' in flask.session
            assert flask.session['csrf_token'] in res.data

class TestPostAuthorize:
    @freeze_time('2015-10-28 10:28:22')
    def test_identify_with_session(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'Rykleos'
                session['csrf_token'] = 'csrftok'

            res = tc.post(
                '/authorize?redirect_uri=http%3A%2F%2Fcivballroom.io%2Fabc&state=12345',
                data={
                    'csrf_token': 'csrftok',
                    'action': 'identify',
                }
            )

            assert res.status_code == 302
            assert res.location == 'http://civballroom.io/abc?state=12345' + \
                '&code=DYmnMVE.CRI0xg.G82dK66f-zNNKGuHQ1LCsDPU63w'

    def test_identify_without_session(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                # This case seems really unlikely, but we need to isolate concerns
                session['csrf_token'] = 'csrftok'

            res = tc.post(
                '/authorize?redirect_uri=http%3A%2F%2Ftest.com',
                data={
                    'csrf_token': 'csrftok',
                    'action': 'identify',
                }
            )

            assert res.status_code == 400

    def test_identify_invalid_redirect_uri(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'Rykleos'
                session['csrf_token'] = 'csrftok'

            res = tc.post(
                '/authorize?redirect_uri=ahhp%3A%2F%2Ftest.com',
                data={
                    'csrf_token': 'csrftok',
                    'action': 'identify',
                }
            )

            assert res.status_code == 400

    def test_identify_invalid_or_missing_csrf_token(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'Rykleos'
                session['csrf_token'] = 'csrftok'

            assert tc.post(
                '/authorize?redirect_uri=http%3A%2F%2Ftest.com',
                data={
                    'csrf_token': 'csrftok2',
                    'action': 'identify',
                }
            ).status_code == 400

            assert tc.post(
                '/authorize?redirect_uri=http%3A%2F%2Ftest.com',
                data={
                    'action': 'identify',
                }
            ).status_code == 400

    def test_decline(self):
        with app.test_client() as tc:
            with tc.session_transaction() as session:
                session['username'] = 'Rykleos'
                session['csrf_token'] = 'csrftok'

            res = tc.post(
                '/authorize?redirect_uri=http%3A%2F%2Ftest.com&state=12345',
                data={
                    'csrf_token': 'csrftok',
                    'action': 'decline',
                }
            )

            assert res.status_code == 302
            assert res.location == 'http://test.com?state=12345&error=declined'

class TestUserInfo:
    # This timestamp is a few seconds after the code's on purpose
    @freeze_time('2015-10-28 10:28:45')
    def test_valid_code(self):
        with app.test_client() as tc:
            res = tc.get('/userinfo?code=DYmnMVE.CRI0xg.G82dK66f-zNNKGuHQ1LCsDPU63w')
            assert res.status_code == 200
            assert json.loads(res.data) == {'user': 'rykleos', 'display_name': 'Rykleos'}

    def test_invalid_code(self):
        with app.test_client() as tc:
            res = tc.get('/userinfo?code=AbCdEfG.CRI0xg.G82dK66f-zNNKGuHQ1LCsDPU63w')
            assert res.status_code == 400

    def test_expired_code(self):
        with app.test_client() as tc:
            res = tc.get('/userinfo?code=DYmnMVE.COy3gA.7d9QCfiz1EWI0SIxPYyPdSiAl4g')
            assert res.status_code == 400
