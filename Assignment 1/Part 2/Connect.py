#!/usr/bin/env python3
"""
Connect - simulated service protected by 2FA (CSCI262 Assignment 1, Part 2).

Usage:
    python3 Connect.py <username> new                    register a new user
    python3 Connect.py <username> <password> <pin>       log in with password + pin

Passwords.txt (current working directory) is cleartext, one user per line:
        <username><TAB><password>
Usernames therefore may not contain whitespace. Only Connect reads/writes this
file; Device never touches it. The file is loaded into a dictionary
(username -> password) for O(1) lookup.

Password appropriateness checks for new users (all must hold):
    - the two entries match
    - at least 8 characters
    - contains no whitespace
    - contains at least one letter and at least one digit
    - is not equal to, and does not contain, the username (case-insensitive)

Pin verification: the pin must equal the pin Device would print in the CURRENT
15-second window (windows aligned to multiples of 15 s since the Unix epoch).
Pins from earlier/later windows are rejected (GRACE_WINDOWS = 0, so the first
pin Device prints is valid only for the remainder of its window). The same
algorithm as Device.py is used; no communication happens between the programs.
"""

"""
Represents the service the user wants to connect to.
Usage — new user:
Connect <username> new
• Prompt the user to enter a password twice and check the two entries match.
• Apply some password appropriateness check (you choose the criteria — e.g., minimum length,
not equal to the username — and document them).
• If the password is acceptable, store username and password in a file named Passwords.txt in the
current working directory.
• Passwords.txt must be cleartext and human-readable, with the password clearly visible. (This
is insecure in practice but simplifies the assignment.) 
"""

import getpass
import hashlib
import hmac
import os
import struct
import sys
import time

WINDOW_SECONDS = 15
DIGITS = 6
GRACE_WINDOWS = 0          # extra previous windows accepted (0 = strict, per spec)
PASSWORD_FILE = "Passwords.txt"


def pin_for(username: str, password: str, window: int) -> str:
    msg = f"{username}:{window}".encode("utf-8")
    mac = hmac.new(password.encode("utf-8"), msg, hashlib.sha256).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def load_users() -> dict:
    users = {}
    if os.path.exists(PASSWORD_FILE):
        with open(PASSWORD_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line or "\t" not in line:
                    continue
                u, p = line.split("\t", 1)
                users[u] = p
    return users


def check_password(username: str, password: str):
    """Return an error message, or None if acceptable."""
    if len(password) < 8:
        return "Password must be at least 8 characters."
    if any(c.isspace() for c in password):
        return "Password must not contain whitespace."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Password must contain at least one letter and one digit."
    if username.lower() in password.lower():
        return "Password must not be or contain the username."
    return None


def new_user(username: str) -> int:
    if not username or any(c.isspace() for c in username):
        print("Failure: username must be non-empty and contain no whitespace.")
        return 1
    if username in load_users():
        print("Failure: that username already exists.")
        return 1
    p1 = getpass.getpass("Enter password: ")
    p2 = getpass.getpass("Re-enter password: ")
    if p1 != p2:
        print("Failure: passwords do not match.")
        return 1
    err = check_password(username, p1)
    if err:
        print("Failure: " + err)
        return 1
    with open(PASSWORD_FILE, "a", encoding="utf-8") as f:
        f.write(f"{username}\t{p1}\n")
    print(f"Success: user '{username}' created.")
    return 0


def login(username: str, password: str, pin: str) -> int:
    users = load_users()
    stored = users.get(username)
    if stored is None or not hmac.compare_digest(stored.encode(), password.encode()):
        print("Failure: invalid username, password or pin.")
        return 1
    window = int(time.time() // WINDOW_SECONDS)
    for w in range(window - GRACE_WINDOWS, window + 1):
        if hmac.compare_digest(pin_for(username, stored, w).encode(), pin.encode()):
            print("Success: authentication successful.")
            return 0
    print("Failure: invalid username, password or pin.")
    return 1


def main() -> None:
    if len(sys.argv) == 3 and sys.argv[2] == "new":
        sys.exit(new_user(sys.argv[1]))
    if len(sys.argv) == 4:
        sys.exit(login(sys.argv[1], sys.argv[2], sys.argv[3]))
    print("Usage:\n  Connect <username> new\n  Connect <username> <password> <pin>")
    sys.exit(1)


if __name__ == "__main__":
    main()