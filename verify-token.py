from jwt_utils import decode_RS256
from auth_policy import AuthPolicy

from settings import (
    ICPDAO_JWT_RSA_PUBLIC_KEY
)

def handler(event, context):
    token = event['authorizationToken']
    methodArn = event['methodArn']

    try:
        payload = decode_RS256(token, ICPDAO_JWT_RSA_PUBLIC_KEY)
        principalId = payload['user_id']
    except:
      raise Exception('Unauthorized')  

    tmp = methodArn.split(':')
    apiGatewayArnTmp = tmp[5].split('/')
    awsAccountId = tmp[4]

    policy = AuthPolicy(principalId, awsAccountId)
    policy.restApiId = apiGatewayArnTmp[0]
    policy.region = tmp[3]
    policy.stage = apiGatewayArnTmp[1]
    policy.allowAllMethods()

    authResponse = policy.build()
    authResponse['context'] = payload
    return authResponse
