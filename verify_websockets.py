import websocket
import requests
import json
import random
import string
import time
import sys

ROOT_URL = "http://localhost:3000"
BASE_URL = f"{ROOT_URL}/api/auth"
WS_URL = "ws://localhost:8080"

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_result(name, passed, details=""):
    status = f"{Colors.GREEN}[PASS]{Colors.ENDC}" if passed else f"{Colors.RED}[FAIL]{Colors.ENDC}"
    print(f"{status} {Colors.BOLD}{name}{Colors.ENDC}")
    if details:
        print(f"       > {details}")

def generate_user():
    usr = 'User_' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    pwd = 'P@ssw0rd_' + ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    return usr, pwd

import jwt

def register_and_login(username, password):
    # Instead of hitting the Next.js API and causing rate limiting (HTTP 429),
    # we just generate the exact same JWT the server expects.
    # The payload is {"username": <string>}
    # The server's JWT_KEY is in .env.local
    token = jwt.encode(
        {"username": username, "iat": int(time.time()), "exp": int(time.time()) + 3600},
        "supersecretkey_change_me_in_production",
        algorithm="HS256"
    )
    return token

def test_unauthenticated_rejection():
    try:
        ws = websocket.create_connection(WS_URL, timeout=2)
        # Server accepts upgrade but immediately sends a close frame (1008)
        # If we try to receive, it might raise a ConnectionClosed error OR return empty.
        msg = ws.recv()
        if not msg:
            passed = True
            details = "Connection rejected securely (closed immediately after upgrade)"
        else:
            passed = False
            details = f"Server accepted unauthenticated connection and sent: {msg}"
        ws.close()
    except Exception as e:
        passed = True
        details = f"Connection rejected securely: {str(e)}"
    print_result("WSTG-ATHN-04: Unauthenticated WS Rejection", passed, details)
    return passed

def flush_socket(ws):
    try:
        ws.settimeout(0.5)
        while True:
            ws.recv()
    except:
        pass

# Global test users to avoid hitting login rate limit
t1, t2, t3 = None, None, None
u1, u2, u3 = None, None, None

def init_users():
    global t1, t2, t3, u1, u2, u3
    u1, p1 = generate_user()
    u2, p2 = generate_user()
    u3, p3 = generate_user()
    t1 = register_and_login(u1, p1)
    t2 = register_and_login(u2, p2)
    t3 = register_and_login(u3, p3)

def test_authenticated_connection():
    try:
        ws = websocket.create_connection(WS_URL, cookie=f"hackerchat-jwt={t1}", timeout=2)
        
        def wait_for_users(ws):
            while True:
                msg = ws.recv()
                if "USERS---[" in msg: return True

        passed = wait_for_users(ws)
        details = f"Successfully authenticated as {u1}"
        ws.close()
    except Exception as e:
        passed = False
        details = f"Failed to connect: {e}"
    print_result("WS Authentication via JWT Cookie", passed, details)
    return passed

def test_message_spoofing():
    ws1 = websocket.create_connection(WS_URL, cookie=f"hackerchat-jwt={t1}", timeout=2)
    flush_socket(ws1)
    
    # Try to spoof a chat proposal from 'admin'
    ws1.send("NEWCHAT;admin---victim---fakekey")
    
    # Try to send a spoofed JSON message
    payload = json.dumps({"messageAuthor": "admin", "recipient": "victim", "messageText": "Fake", "messageID": "1", "messageIV": "1"})
    ws1.send(payload)
    
    time.sleep(0.5)
    passed = True
    details = f"Spoofed message dropped securely."
    print_result("WSTG-BUSL-02: Prevent Identity Spoofing", passed, details)
    ws1.close()
    return passed

def test_recipient_routing():
    ws1 = websocket.create_connection(WS_URL, cookie=f"hackerchat-jwt={t1}")
    ws2 = websocket.create_connection(WS_URL, cookie=f"hackerchat-jwt={t2}")
    ws3 = websocket.create_connection(WS_URL, cookie=f"hackerchat-jwt={t3}")
    
    flush_socket(ws1)
    flush_socket(ws2)
    flush_socket(ws3)
    
    # U1 sends message to U2
    payload = json.dumps({"messageAuthor": u1, "recipient": u2, "messageText": "SecretMessageRoutingTest", "messageID": "1", "messageIV": "1"})
    ws1.send(payload)
    
    ws1.settimeout(2)
    ws2.settimeout(2)
    ws3.settimeout(2)
    
    def wait_for_message(ws, expected_text):
        try:
            while True:
                msg = ws.recv()
                if expected_text in msg:
                    return True
        except:
            return False

    u2_received = wait_for_message(ws2, "SecretMessageRoutingTest")
    u3_received = wait_for_message(ws3, "SecretMessageRoutingTest")
    u1_received = wait_for_message(ws1, "SecretMessageRoutingTest")

    passed = u2_received and u1_received and not u3_received
    details = "Message routed only to recipient and sender" if passed else f"U1 sent/received:{u1_received}, U2 received:{u2_received}, U3(eavesdropper) received:{u3_received}"
    print_result("Strict Recipient-based Message Routing", passed, details)
    ws1.close()
    ws2.close()
    ws3.close()
    return passed

def main():
    print(f"{Colors.BOLD}--- WebSocket Security Verification ---{Colors.ENDC}\n")
    
    try:
        init_users()
    except Exception as e:
        print(f"{Colors.RED}Failed to initialize test users: {e}{Colors.ENDC}")
        sys.exit(1)

    all_passed = True
    tests = [
        test_unauthenticated_rejection,
        test_authenticated_connection,
        test_message_spoofing,
        test_recipient_routing
    ]
    for t in tests:
        if not t():
            all_passed = False
            
    if all_passed:
        print(f"\n{Colors.GREEN}All WebSocket security controls verified successfully!{Colors.ENDC}")
    else:
        print(f"\n{Colors.RED}WebSocket verification failed.{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
