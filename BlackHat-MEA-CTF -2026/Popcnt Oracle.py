"""
RSA Oracle Binary Search Solver for CTF Challenges.

This script connects to a remote RSA oracle service, retrieves the public key (e, n)
and the ciphertext (c). It then exploits the oracle using a binary search algorithm
(often related to LSB or parity oracle attacks) to decrypt the ciphertext and
recover the original message (the flag).
"""

import socket
import sys

# Increase the limit for integer-to-string conversion to handle very large RSA numbers
sys.set_int_max_str_digits(10000)

# --- Configuration ---
HOST = 'tcp.flagyard.com'
PORT = 17429

def recv_until(s, delim):
    """
    Reads data from the socket one byte at a time until the specified delimiter is found.
    
    Args:
        s (socket): The active socket connection.
        delim (bytes): The byte string delimiter to look for.
        
    Returns:
        bytes: The accumulated data up to and including the delimiter.
    """
    data = b""
    while not data.endswith(delim):
        char = s.recv(1)
        if not char:
            break
        data += char
    return data

def main():
    """
    Main execution flow: connects to the server, parses RSA parameters,
    performs the binary search attack, and submits the recovered message.
    """
    # 1. Establish the connection to the CTF server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    print(f"[*] Connected to {HOST}:{PORT}")

    # 2. Receive and parse the foundational RSA variables (e, n, c)
    recv_until(s, b"e = ")
    e = int(recv_until(s, b"\n").strip())
    
    recv_until(s, b"n = ")
    n = int(recv_until(s, b"\n").strip())
    
    recv_until(s, b"c = ")
    c = int(recv_until(s, b"\n").strip())
    
    print("[+] Variables received successfully: e, n, c.")

    # 3. Send the original ciphertext to get the initial reference weight/parity
    recv_until(s, b"x> ")
    s.sendall(str(c).encode() + b"\n")
    prev_w = int(recv_until(s, b"\n").strip())

    # Initialize binary search boundaries
    low = 0
    high = n
    multiplier = 1

    print("[+] Searching for the flag... this may take a moment.")

    # 4. Binary search algorithm to extract the secret message
    # We iterate for every bit in the modulus 'n'
    for i in range(1, n.bit_length() + 1):
        # Double the multiplier modulo n
        multiplier = (multiplier * 2) % n
        
        # Construct the chosen ciphertext: c * (multiplier^e) mod n
        c_test = (c * pow(multiplier, e, n)) % n
        
        # Query the oracle with the chosen ciphertext
        recv_until(s, b"x> ")
        s.sendall(str(c_test).encode() + b"\n")
        current_w = int(recv_until(s, b"\n").strip())
        
        mid = (low + high) // 2
        
        # Update boundaries based on the oracle's response
        if current_w == prev_w:
            high = mid
        else:
            low = mid
            
        prev_w = current_w

    print(f"[+] Done! Recovered message (m): {high}")

    # 5. Send the final recovered message back to the server to get the flag
    recv_until(s, b"x> ")
    s.sendall(str(high).encode() + b"\n")

    # 6. Read and print the final response (the flag)
    response = s.recv(4096).decode(errors="replace")
    print(f"\n[ FLAG ]\n{response}")
    
    s.close()

if __name__ == "__main__":
    main()
