
"""
Stage 1 solver for the 'hokan' CTF challenge.

This script connects to the challenge service, sends 8 mathematical queries
based on the first 11 prime numbers (x_j = q_j^t for t = 0..7), and collects
the raw sequence of responses (y_0..y_7). 

This is a data-collection stage. It does not perform the final recovery 
but gathers the necessary sequence to reason about the recurrence order/modulus.
"""

import socket
import sys

# --- Configuration ---
HOST = "tcp.flagyard.com"
PORT = 14500

# The first 11 prime numbers used as base values for the variables x0..x10
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]


def recvuntil(sock, marker=b"> ", timeout=10):
    """
    Reads data from the socket sequentially until a specific marker is found.
    
    Args:
        sock (socket): The active socket connection.
        marker (bytes): The byte string to look for (default is the prompt "> ").
        timeout (int): Socket timeout in seconds.
        
    Returns:
        bytes: The accumulated data containing the marker.
    """
    sock.settimeout(timeout)
    data = b""
    
    # Keep reading in chunks of 4096 bytes until the marker appears in our buffer
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        
    return data


def main():
    """
    Main execution flow: establishes connection, generates mathematical payloads,
    sends them to the server, and robustly parses the returned sequence.
    """
    # 1. Establish the TCP connection to the CTF server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((HOST, PORT))

    ys = []  # Array to store the collected mathematical sequence
    
    # 2. Loop 8 times to send queries for t = 0 to 7
    for t in range(8):
        # Wait for the server's input prompt ("> ")
        banner = recvuntil(s, b"> ")
        sys.stderr.write(f"[recv before query {t}] {banner!r}\n")

        # Calculate q^t for each prime number in the PRIMES list
        v = [pow(q, t) for q in PRIMES]
        
        # Format the payload as comma-separated values ending with a newline
        line = ",".join(str(x) for x in v) + "\n"
        sys.stderr.write(f"[send t={t}] {line.strip()[:80]}...\n")
        
        # Send the calculated payload to the server
        s.sendall(line.encode())

        # Read the server's response up to the newline character
        resp = recvuntil(s, b"\n", timeout=10)
        sys.stderr.write(f"[raw resp] {resp!r}\n")
        
        # 3. Parse the integer response securely
        try:
            # Attempt direct conversion if the response is clean
            y = int(resp.strip())
        except ValueError:
            # Fallback: if the prompt and value arrive in the same chunk,
            # split the text and extract the last token that looks like a number.
            tokens = [tok for tok in resp.split() if tok.strip(b"-").isdigit()]
            y = int(tokens[-1]) if tokens else None
            
        ys.append(y)
        print(f"t={t}  y_t = {y}")

    # 4. Print the final collected sequence to the user
    print("\n--- collected sequence (copy this back) ---")
    print(ys)

    # 5. Optional cleanup: check if any trailing/extra data was sent by the server
    s.settimeout(2)
    try:
        tail = s.recv(4096)
        if tail:
            sys.stderr.write(f"[extra] {tail!r}\n")
    except Exception:
        pass

    # Close the connection cleanly
    s.close()


if __name__ == "__main__":
    main()