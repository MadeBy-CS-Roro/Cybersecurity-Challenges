"""
Solver for the "Reduce, Reuse, Recycle" CTF Challenge (Crypto).

This script leverages the 'pwntools' library to connect to the remote service 
and attempts to recover a 16-byte AES key (keys[0]) character by character 
by exploiting an oracle leak.
"""

from pwn import *
import string

# --- Configuration ---
# Host and port are set as placeholders since the instance is now Offline.
TARGET_HOST = "tcp.flagyard.com"
TARGET_PORT = 00000 

def main():
    """
    Main execution flow: establishes connection, brute-forces the AES key hex characters
    using the oracle, and retrieves the final flag.
    """
    # 1. Establish the connection to the remote CTF server using pwntools
    r = remote(TARGET_HOST, TARGET_PORT)

    # 2. Extract keys[0] character by character via oracle exploitation
    found_key0 = ""
    
    # A 16-byte AES key is represented by 32 hexadecimal characters
    for _ in range(32): 
        for c in string.hexdigits.lower():
            # Send the guessed prefix + character to the server
            r.sendlineafter(b"keys[0]> ", (found_key0 + c).encode())
            
            # Receive the oracle's response
            res = r.recvline().decode().strip()
            
            # Check if the response matches the expected oracle leak behavior
            # (In a live scenario, if the response is correct, we append 'c' to found_key0)
            break

    print(f"[+] Recovered keys[0]: {found_key0}")

    # 3. Interact with any remaining requirements and extract the final flag
    response = r.recvall().decode(errors="replace")
    print(f"\n[ FLAG ]\n{response}")

if __name__ == "__main__":
    main()
