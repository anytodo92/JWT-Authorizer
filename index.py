from auth import Auth
from reponse import Response

def main():
    data = Auth.authenticate(event)
    Response.success(response)
    #Auth.authenticate_for_test()

if __name__ == '__main__':
    main()



