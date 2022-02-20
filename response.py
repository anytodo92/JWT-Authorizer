from typing import Tuple

class Response:
    def __init__(self):
        print('MGResponse init')
    
    @staticmethod
    def success(body) -> Tuple:
        response = {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'isBase64Encoded': False,
            #'multiValueHeaders': { 
            #'X-Custom-Header': ['My value', 'My other value'],
            #},
            'body': body
        }
        return response

    @staticmethod
    def error(error) -> Tuple:
        response = {
            'statusCode': error.code,
            'headers': {
            'Content-Type': 'text/plain',
            'x-amzn-ErrorType': error.code
            },
            'isBase64Encoded': False,
            'body': error
        }  
        return response