#!/usr/bin/env python3
"""
Device - simulated 2FA authenticator (CSCI262 Assignment 1, Part 2).

Usage:  python3 Device.py <username> <password>
        e.g. python3 Device.py Alice 1wdcasFga

Prints a 6-digit one-time pin (as a string, leading zeros kept) once per
15-second time window, in the form "Device: 107283".

Pin algorithm (pre-agreed with Connect.py, never communicated at run time):
    window = floor(unix_time / 15)
    mac    = HMAC-SHA256(key = password, message = username + ":" + window)
    pin    = (31-bit value from 4 bytes of mac chosen by the low nibble of the
              last byte, as in RFC 4226 "dynamic truncation") mod 10^6,
             zero-padded to 6 digits.

First-pin rule: windows are aligned to the system clock (window boundaries are
at multiples of 15 s since the Unix epoch). The first pin is printed
immediately and is valid only for the REMAINDER of the current window (so it
may be valid for less than 15 s). A new pin is then printed at every window
boundary.

This program does not validate the username/password and does not read or
write any file or communicate with Connect in any way.
"""

"""
Represents the user's authenticator device. It produces one-time 6-digit pins that the user will type
into Connect.
Usage:
Device <username> <password>
Example:
Device Alice 1wdcasFga
• Device does not validate the username or password. Any values are accepted.
• Device repeatedly prints a new 6-digit pin (as a string, leading zeros allowed) every 15 seconds, in
this format:
Device: 107283
Device: 837223
Device: 012123
Device: 492832
Device: 217281
• Each pin must be a deterministic function of (username, password, current time window) such
that Connect, knowing the username and password and reading the same clock, can
independently compute and verify the pin.

• Time window rule: Divide time into 15-second windows. A pin printed during window W is valid for
the duration of window W. Decide and document how you handle the very first pin — for example,
whether it is valid for the remainder of the current window (possibly less than 15 seconds) or
whether printing the first pin starts a fresh 15-second window. Either choice is acceptable if
documented clearly.
• You do not need to track which pins have already been used.
"""
import hashlib
import hmac
import struct
import sys
import time

WINDOW_SECONDS = 15
DIGITS = 6


def pin_for(username: str, password: str, window: int) -> str:
    msg = f"{username}:{window}".encode("utf-8")
    mac = hmac.new(password.encode("utf-8"), msg, hashlib.sha256).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** DIGITS)).zfill(DIGITS)


def main() -> None:
    if len(sys.argv) != 3:
        print("Usage: Device <username> <password>")
        sys.exit(1)
    username, password = sys.argv[1], sys.argv[2]
    last_window = None
    try:
        while True:
            now = time.time()
            window = int(now // WINDOW_SECONDS)
            if window != last_window:
                print(f"Device: {pin_for(username, password, window)}", flush=True)
                last_window = window
            # sleep until the next window boundary (small margin avoids early wake-up)
            next_boundary = (window + 1) * WINDOW_SECONDS
            time.sleep(max(0.0, next_boundary - time.time()) + 0.01)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()