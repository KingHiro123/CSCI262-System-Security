Files used for this:
Device.py (Representing the user’s authenticator device), Connect.py (Represents the service the user wants to connect to) and Passwords.txt (user file that is used by Connect.py, mainly for creating and storing users made). All of this is written with Python, using only the standard libraries like: hashlib, hmac, struct, time, getpass.

1. How to run the program
Device.py
python3 Device.py <name of user> <Password>
This line will launch the program and print a new pin every 15 seconds, Ctrl + C to stop the program.

Connect.py
python3 Connect.py <name of user> new
This line will register a new user with your user. It will prompt you to enter a password, once you enter a password, you are required to re-enter the same password, for password checking. Once the passwords are valid, it will prompt a success message saying “Passwords are matched, user is registered”. The user will then be created and stored in the Passwords.txt file.

python3 Connect.py <name of user> <password> <pin> 
This line will check whether the user you entered with and the pin are the same. If they match, there will be a message saying “Verification Successful”. If not, there will be a message saying "Failure: invalid username, password or pin.” and end the program.


1. Connect.py’s checks and files
For a new user, the username must be new, non-empty and have no spaces. The password must be at least 8 characters, have no spaces, contain a letter and a digit, and not contain the username. It is checked as soon as it is typed, before asking for it a second time. Passwords.txt is plain text, one user per line, as username<TAB>password, and each new user always goes on a new line. Every failed login gives the same message, so it doesn’t say which part was wrong. 


3. Testing summary
A valid new user was saved. A short password, mismatched passwords and a password containing the username were all rejected.
Device printed pins in the form Device: 416725, with a new pin every 15 seconds.
Connect accepted the current pin. It rejected a wrong pin, a wrong password, and an expired pin.
