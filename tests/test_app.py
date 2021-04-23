import os
import pytest

from jwt_utils import encode_RS256, decode_RS256

TESTS_ROOT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)))

public_key = open('{}/rs256/rsa-public-key.pem'.format(TESTS_ROOT_DIR), 'r').read()
private_key = open('{}/rs256/rsa-private-key.pem'.format(TESTS_ROOT_DIR), 'r').read()
os.environ['ICPDAO_JWT_RSA_PUBLIC_KEY'] = public_key

from verify_token import handler

class TestApp():
    def test_app(self):
        payload = {
            "user_id": "mockid"
        }
        token = encode_RS256(payload, private_key)

        content = decode_RS256(token, public_key)
        assert content['user_id'] == 'mockid'

        res = handler({
            'authorizationToken': token,
            'methodArn': 'arn:aws:execute-api:4:5:6/7'
        }, None)

        assert res['context']['user_id'] == 'mockid'
        assert res['policyDocument']['Statement'][0]['Effect'] == 'Allow'
        assert res['policyDocument']['Statement'][0]['Resource'][0] == 'arn:aws:execute-api:4:5:6/7/*/*'
