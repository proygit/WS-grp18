# WB-CBS-Group-18 for the USER with JWT Authorization and access token
The below method calls are done using the URL as mentioned from a WINDOWS terminal

1. **Register new user: Inorder to register first run the secrets.py and add the jwt-secret token in the code.
  do a post api request with->username and password  to register a new user

2. **Login with correct credentials** Correct credentials are needed to login .Also checks if User is already registered or is present in DB.

#NOTE protected method could be used to grant access ONLY to protected USERS ONLY

3.**GET protected** This method only shows the user name when the user is verified with proper *Authorization Header*  and *access token*
 of that particular user
