import string
from typing import Any, Tuple, List
import jwt
from jwt import PyJWKClient
import re
from auth0.v3.authentication.token_verifier import TokenVerifier, AsymmetricSignatureVerifier, TokenValidationError

class Auth:
    def __init__(self):
        print('Auth init')
    
    @staticmethod
    def authenticate_for_test(self):   
        token_string = 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik5FRTFRVVJCT1RNNE16STVSa0ZETlRZeE9UVTFNRGcyT0Rnd1EwVXpNVGsxUWpZeVJrUkZRdyJ9.eyJpc3MiOiJodHRwczovL2Rldi04N2V2eDlydS5hdXRoMC5jb20vIiwic3ViIjoiYVc0Q2NhNzl4UmVMV1V6MGFFMkg2a0QwTzNjWEJWdENAY2xpZW50cyIsImF1ZCI6Imh0dHBzOi8vZXhwZW5zZXMtYXBpIiwiaWF0IjoxNTcyMDA2OTU0LCJleHAiOjE1NzIwMDY5NjQsImF6cCI6ImFXNENjYTc5eFJlTFdVejBhRTJINmtEME8zY1hCVnRDIiwiZ3R5IjoiY2xpZW50LWNyZWRlbnRpYWxzIn0.PUxE7xn52aTCohGiWoSdMBZGiYAHwE5FYie0Y1qUT68IHSTXwXVd6hn02HTah6epvHHVKA2FqcFZ4GGv5VTHEvYpeggiiZMgbxFrmTEY0csL6VNkX1eaJGcuehwQCRBKRLL3zKmA5IKGy5GeUnIbpPHLHDxr-GXvgFzsdsyWlVQvPX2xjeaQ217r2PtxDeqjlf66UYl6oY6AqNS8DH3iryCvIfCcybRZkc_hdy-6ZMoKT6Piijvk_aXdm7-QQqKJFHLuEqrVSOuBqqiNfVrG27QzAPuPOxvfXTVLXL2jek5meH6n-VWgrBdoMFH93QEszEDowDAEhQPHVs0xj7SIzA'  
        match = re.search('Bearer (.*)', token_string)
        token = match.group(1)
        if (token is None or token == ""):
            print('Invalid Authorization token - ', token_string ,' does not match "Bearer .*"')
        
        kid = 'NEE1QURBOTM4MzI5RkFDNTYxOTU1MDg2ODgwQ0UzMTk1QjYyRkRFQw'           
        url = 'https://dev-87evx9ru.auth0.com/.well-known/jwks.json'
        jwks_client = PyJWKClient(url)
        
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)

            data = jwt.decode(
                token,
                signing_key.key,
                algorithms = ['RS256'],
                audience='https://expenses-api',
                options = {'verify_exp': False},
            )
            print(data)
        except:
            print('It is occurred any error in the progress to authorize the JWT.')

    @staticmethod
    def authenticate(self, params) -> Any:
        token = self.get_token(params)
        if (not token):
            return False

        url = 'https://dev-slpzx1p8.us.auth0.com/.well-known/jwks.json'
        jkws_client = PyJWKClient(url)
        signing_key = jkws_client.get_signing_key_from_jwt(token)
        try:
            data  = jwt.decode(token, signing_key.key, algorithms = ['RS256'])
            res = {
                'principalId': data['sub'],
                'policyDocument': self.get_policy_document('Allow', params['methodArn']),
                'context': { 'scope': data['scope'] }
            }
            return res
        except:
            print('It is occurred any error in the progress to authorize by using API which JWT provided.')

    @staticmethod
    def get_token(self, params) -> string:
        if (not params['type'] or params['type'] != 'TOKEN'):
            print('Expected "event.type" parameter to have value "TOKEN"')
        
        token_string = params['authorizationToken']
        if (not token_string or token_string == ""):
            print('Expected "event.authorizationToken" parameter to be set')

        match = re.search('Bearer (.*)', token_string)
        token = match.group(1)
        if (not token or token == ''):
            print('Invalid Authorization token - ', token_string ,' does not match "Bearer .*"')
        
        return token

    @staticmethod
    def get_policy_document(self, effect, resource) -> Tuple:
        policy_document = {
            'Version': '2012-10-17', # default version
            'Statement': [{
                'Action': 'execute-api:Invoke', # default action
                'Effect': effect,
                'Resource': resource
            }]
        }

        return policy_document

    @staticmethod
    def verfiy_token(self, params) -> bool:
        domain = 'dev-slpzx1p8.us.auth0.com'
        client_id = 'MiB2SyiUfd6k6rEfE4HY78gBB7i2qXHa'
        token = self.get_token(params)

        jwks_url = 'https://{}/.well-known/jwks.json'.format(domain)
        issuer = 'https://{}/'.format(domain)
        sv = AsymmetricSignatureVerifier(jwks_url)
        tv = TokenVerifier(signature_verifier=sv, issuer=issuer, audience=client_id)

        try:
            tv.verify(token, organization='org_abc')
            return True
        except TokenValidationError:
            return False
