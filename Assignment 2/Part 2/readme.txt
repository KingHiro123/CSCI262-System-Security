CSCI262 Assignment 2 - Part Two
File System with login authentication and access control

 
LANGUAGE AND REQUIREMENTS
- Python 3 (tested with 3.13; any Python 3.8 or later works).
- No compilation and no extra packages. Only the standard library is used.
 
FILES
- FileSystem.py  the program
- salt.txt       Username:Salt            (8 random digits)
- shadow.txt     Username:MD5(password+salt):Clearance
- Files.store    saved file records, one "Filename:Level" per line
 
salt.txt and shadow.txt are created blank automatically if they do not exist.
Files.store is created when you choose Save.
 
HOW TO RUN
1. Open a terminal in the folder containing FileSystem.py.
2. Create a user:
       python3 FileSystem.py -i
   Enter a username, the password twice, and a clearance (0, 1, 2 or 3).
   Repeat to create more users.
3. Log in and use the file system:
       python3 FileSystem.py
   Enter the username and password (shown as *).
   (On some systems use "python" instead of "python3".)
 
Every run first prints the MD5 test line:
   MD5 ("This is a test") = ce114e4501d2f4e2dcea3e17b546f339
(it is computed at run time, not hard coded).
 
PASSWORD RULES
At least 8 characters; at least one uppercase letter, one lowercase letter and
one digit; no spaces or ':'; must not contain the username.
A warning listing the requirements is shown if a rule is not met.
 
MENU
Options: (C)reate, (R)ead, (W)rite, (L)ist, (S)ave or (E)xit.
- C  create a file record (filename and level 0-3); refused if it already exists
- R  read check
- W  write check
- L  list all file records
- S  save all records to Files.store (human readable)
- E  exit, after confirming with Y
Files are only records held in memory; no real files are created.
Files.store is loaded automatically after login if it exists.
 
ACCESS CONTROL (levels 0 < 1 < 2 < 3)
- Read allowed only if the user's clearance >= file level (no read up).
- Write allowed only if the user's clearance <= file level (no write down).
 
EXAMPLE
User Bob with clearance 1 creates alpha (level 0) and beta (level 2):
- Read alpha: allowed.    Read beta: denied.
- Write alpha: denied.    Write beta: allowed.
