#!/usr/bin/env python3
"""
CSCI262 Assignment 2 - Part Two
File System with login authentication and access control

Usage:
    python3 FileSystem.py -i     create a new user (needs salt.txt / shadow.txt; created blank if missing)
    python3 FileSystem.py        log in and use the file system

Levels: 0 < 1 < 2 < 3 (0 dominated by 1,2,3; 1 dominated by 2,3; 2 dominated by 3).
Bell-LaPadula:
    ss-property (simple security): read allowed only if user clearance >= file level (no read up)
    *-property  (star):            write allowed only if user clearance <= file level (no write up/down: no write down)
"""
import hashlib
import os
import re
import secrets
import sys

SALT_FILE = "salt.txt"
SHADOW_FILE = "shadow.txt"
STORE_FILE = "Files.store"


# ---------------------------------------------------------------- MD5
def md5_hex(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def md5_self_test():
    # Computed at run time (not hard-coded).
    print('MD5 ("This is a test") = ' + md5_hex("This is a test"))


# ---------------------------------------------------------------- helpers
def read_pairs(path):
    """Return list of lines split on ':' (ignoring blank lines)."""
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [ln.rstrip("\n").split(":") for ln in f if ln.strip()]


def lookup_salt(username):
    for parts in read_pairs(SALT_FILE):
        if len(parts) >= 2 and parts[0] == username:
            return parts[1]
    return None


def lookup_shadow(username):
    for parts in read_pairs(SHADOW_FILE):
        if len(parts) >= 3 and parts[0] == username:
            return parts[1], parts[2]
    return None


def read_password(prompt):
    """Read a password, echoing '*' for every character typed."""
    if not sys.stdin.isatty():
        return input(prompt)               # piped input (testing)
    sys.stdout.write(prompt)
    sys.stdout.flush()
    chars = []
    try:
        import msvcrt                      # Windows
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop()
                    sys.stdout.write("\b \b")
            else:
                chars.append(ch)
                sys.stdout.write("*")
            sys.stdout.flush()
    except ImportError:                    # Linux / macOS
        import termios, tty
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            while True:
                ch = sys.stdin.read(1)
                if ch in ("\r", "\n"):
                    break
                if ch == "\x03":
                    raise KeyboardInterrupt
                if ch == "\x04" and not chars:
                    raise EOFError
                if ch in ("\x7f", "\b"):
                    if chars:
                        chars.pop()
                        sys.stdout.write("\b \b")
                else:
                    chars.append(ch)
                    sys.stdout.write("*")
                sys.stdout.flush()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    sys.stdout.write("\n")
    return "".join(chars)


def read_level(prompt):
    while True:
        v = input(prompt).strip()
        if v in ("0", "1", "2", "3"):
            return int(v)
        print("Invalid level. Please enter 0, 1, 2 or 3.")


REQUIREMENTS = ("Password requirements: at least 8 characters, contain an uppercase letter, "
                "a lowercase letter and a digit, no spaces or ':' characters, and must not "
                "contain the username.")


def password_problems(username, pw):
    problems = []
    if len(pw) < 8:
        problems.append("too short (minimum 8 characters)")
    if not re.search(r"[A-Z]", pw):
        problems.append("needs an uppercase letter")
    if not re.search(r"[a-z]", pw):
        problems.append("needs a lowercase letter")
    if not re.search(r"[0-9]", pw):
        problems.append("needs a digit")
    if re.search(r"[\s:]", pw):
        problems.append("must not contain spaces or ':'")
    if username.lower() in pw.lower():
        problems.append("must not contain the username")
    return problems


# ---------------------------------------------------------------- user creation (-i)
def create_user():
    open(SALT_FILE, "a").close()      # create blank files if they don't exist
    open(SHADOW_FILE, "a").close()

    username = input("Username: ").strip()
    if not username or ":" in username or " " in username:
        print("Invalid username (must be non-empty, no spaces or ':').")
        return
    if lookup_salt(username) is not None or lookup_shadow(username) is not None:
        print("User '%s' already exists. Terminating." % username)
        return

    pw = read_password("Password: ")
    pw2 = read_password("Confirm Password: ")
    if pw != pw2:
        print("Passwords do not match. Terminating.")
        return
    problems = password_problems(username, pw)
    if problems:
        print("Password not acceptable: " + "; ".join(problems) + ".")
        print(REQUIREMENTS)
        return

    clearance = read_level("User clearance (0 or 1 or 2 or 3): ")
    salt = "".join(secrets.choice("0123456789") for _ in range(8))
    pass_salt_hash = md5_hex(pw + salt)

    with open(SALT_FILE, "a") as f:
        f.write("%s:%s\n" % (username, salt))
    with open(SHADOW_FILE, "a") as f:
        f.write("%s:%s:%d\n" % (username, pass_salt_hash, clearance))
    print("User '%s' created with clearance %d." % (username, clearance))


# ---------------------------------------------------------------- authentication
def authenticate():
    username = input("Username: ").strip()
    pw = read_password("Password: ")

    salt = lookup_salt(username)
    if salt is None:
        print("User '%s' not found in %s. Authentication failed." % (username, SALT_FILE))
        return None
    print("%s found in %s" % (username, SALT_FILE))
    print("salt retrieved: " + salt)
    print("hashing ...")
    h = md5_hex(pw + salt)
    print("hash value: " + h)

    entry = lookup_shadow(username)
    if entry is None or entry[0] != h:
        print("Authentication failed: hash does not match %s." % SHADOW_FILE)
        return None
    clearance = int(entry[1])
    print("Authentication for user %s complete." % username)
    print("The clearance for %s is %d." % (username, clearance))
    return username, clearance


# ---------------------------------------------------------------- file store
def load_store():
    files = {}
    if os.path.exists(STORE_FILE):
        with open(STORE_FILE) as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                name, _, lvl = ln.rpartition(":")
                if name and lvl in ("0", "1", "2", "3"):
                    files[name] = int(lvl)
        print("Loaded %d file record(s) from %s." % (len(files), STORE_FILE))
    return files


def save_store(files):
    with open(STORE_FILE, "w") as f:
        f.write("# Filename:SecurityLevel\n")
        for name, lvl in files.items():
            f.write("%s:%d\n" % (name, lvl))
    print("Saved %d file record(s) to %s." % (len(files), STORE_FILE))


# ---------------------------------------------------------------- Bell-LaPadula
def can_read(user_level, file_level):
    return user_level >= file_level        # ss-property: no read up


def can_write(user_level, file_level):
    return user_level <= file_level        # *-property: no write down


MENU = "Options: (C)reate, (R)ead, (W)rite, (L)ist, (S)ave or (E)xit."


def session(username, clearance, files):
    while True:
        print(MENU)
        choice = input("> ").strip().upper()
        if choice == "C":
            name = input("Filename: ").strip()
            if not name or ":" in name:
                print("Invalid filename.")
                continue
            lvl = read_level("Security level (0 or 1 or 2 or 3): ")
            if name in files:
                print("File '%s' already exists." % name)
            else:
                files[name] = lvl
                print("File '%s' created at level %d." % (name, lvl))
        elif choice in ("R", "W"):
            name = input("Filename: ").strip()
            if name not in files:
                print("File '%s' does not exist." % name)
                continue
            lvl = files[name]
            if choice == "R":
                if can_read(clearance, lvl):
                    print("Read of '%s' succeeded (user %d >= file %d, ss-property)." % (name, clearance, lvl))
                else:
                    print("Read of '%s' DENIED: ss-property forbids reading up (user %d < file %d)." % (name, clearance, lvl))
            else:
                if can_write(clearance, lvl):
                    print("Write to '%s' succeeded (user %d <= file %d, *-property)." % (name, clearance, lvl))
                else:
                    print("Write to '%s' DENIED: *-property forbids writing down (user %d > file %d)." % (name, clearance, lvl))
        elif choice == "L":
            if not files:
                print("(no files)")
            for name, lvl in files.items():
                print("  %s  [level %d]" % (name, lvl))
        elif choice == "S":
            save_store(files)
        elif choice == "E":
            ans = input("Shut down the FileSystem? (Y)es or (N)o ").strip().upper()
            if ans == "Y":
                print("Goodbye.")
                return
        else:
            print("Unknown option.")


def main():
    md5_self_test()
    if len(sys.argv) > 1 and sys.argv[1] == "-i":
        create_user()
        return
    result = authenticate()
    if result is None:
        sys.exit(1)
    username, clearance = result
    files = load_store()
    session(username, clearance, files)


if __name__ == "__main__":
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        print("\nExiting.")