#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import socket
from bbs.bbs_plus import BBSPlus
from bbs.curve import BilinearGroup
from bbs.curve import BilinearGroup

class BBSClient:
    def __init__(self, ports, threshold):
        self.ports = ports
        self.threshold = threshold
        self.bbs = BBSPlus()
        self.pk = None

    def send_req(self, port, req):
        try:
            # using TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect(('localhost', port))
            
            s.send(json.dumps(req).encode('utf-8'))
            resp_data = s.recv(8192).decode('utf-8')
            resp = json.loads(resp_data)
            
            s.close()
            return resp
            
        except Exception as e:
            print(f"Port {port} failed: {e}")
            return None

    def init_system(self, msg_len):
        setup_req = {
            'type': 'setup',
            'message_length': msg_len,
            'threshold': self.threshold,
            'total_servers': len(self.ports)
        }
        
        ready_setups = 0
        
        for port in self.ports:
            print(f"Setup server {port}")
            resp = self.send_req(port, setup_req)
            
            if resp and resp.get('success'):
                if self.pk is None:
                    # Get public key from first server
                    raw_pk = resp.get('public_key')
                    try:
                        g = BilinearGroup()
                        X = g.deserialize_g2_point(raw_pk['X'])
                        H = [g.deserialize_g1_point(h) for h in raw_pk['H']]
                        self.pk = {'X': X, 'H': H}
                        print(f"Got public key from {port}")
                    except Exception as e:
                        print(f"PK deserialize failed: {e}")
                        continue
                
                ready_setups += 1
                print(f"Server {port} OK")
            else:
                print(f"Server {port} failed")
        
        if ready_setups >= self.threshold:
            print("Servers ready")
            return True
        else:
            print("Not enough servers")
            return False

    def sign(self, messages):
        if not self.pk:
            print("Not initialized")
            return None
            
        print(f"Signing: {messages}")
        
        # Get partial signatures
        sign_req = {'type': 'sign', 'messages': messages, 'threshold': self.threshold}
        
        partial_sigs = []
        working_ports = []
        
        for port in self.ports:
            if len(partial_sigs) >= self.threshold:
                break
                
            print(f"Getting partial sig from {port}")
            resp = self.send_req(port, sign_req)
            
            if resp and resp.get('success'):
                partial_sig = resp.get('partial_signature')
                if partial_sig:
                    partial_sigs.append(partial_sig)
                    working_ports.append(port)
                    print(f"Got partial from {port}")
            else:
                print(f"Partial failed from {port}")
        
        if len(partial_sigs) < self.threshold:
            print(f"Not enough partials ({len(partial_sigs)}/{self.threshold})")
            return None
        
        print(f"Got {len(partial_sigs)} partials")
        
        # Combine signatures
        combine_req = {
            'type': 'combine',
            'partial_signatures': partial_sigs,
            'messages': messages
        }
        
        # Try working server for combine
        for port in working_ports:
            print(f"Combining at {port}")
            resp = self.send_req(port, combine_req)
            
            if resp and resp.get('success'):
                final_sig = resp.get('signature')
                
                if final_sig and 'A' in final_sig:
                    try:

                        g = BilinearGroup()
                        A = g.deserialize_g1_point(final_sig['A'])
                        final_sig['A'] = A
                        
                        print("Signature ready")
                        return final_sig
                        
                    except Exception as e:
                        print(f"Sig deserialize failed: {e}")
                        continue
        
        print("Combine failed")
        return None

    def verify(self, messages, sig):
        if not self.pk or not sig:
            print("Missing pk or sig")
            return False
            
        print("Verifying...")
        
        try:
            valid = self.bbs.verify(self.pk, messages, sig)
            if valid:
                print("Verify: PASS")
            else:
                print("Verify: FAIL")
            return valid
            
        except Exception as e:
            print(f"Verify error: {e}")
            return False

    """Test blind signature functionality"""
    def test_blind_signature(self, messages, public_info, private_info):
        if not self.pk:
            print("Not initialized")
            return None
            
        print(f"Testing blind signature...")
        print(f"Messages: {messages}")
        print(f"Public info: {public_info}")
        print(f"Private info: {private_info}")
        
        # Simple blind signature test - just use dummy blinding_nonce_e and blinding_nonce_s
        blinding_nonce_e = 123
        blinding_nonce_s = 456
        
        # Create blind signing request
        blind_req = {
            'type': 'blind_sign',
            'messages': messages,
            'public_info': public_info,
            'private_info': private_info,
            'blinding_nonce_e': blinding_nonce_e,
            'blinding_nonce_s': blinding_nonce_s,
            'threshold': self.threshold
        }
        
        # Get partial blind signatures
        partial_sigs = []
        working_ports = []
        
        for port in self.ports:
            if len(partial_sigs) >= self.threshold:
                break
                
            print(f"Getting blind partial sig from {port}")
            resp = self.send_req(port, blind_req)
            
            if resp and resp.get('success'):
                partial_sig = resp.get('partial_signature')
                if partial_sig:
                    partial_sigs.append(partial_sig)
                    working_ports.append(port)
                    print(f"Got blind partial from {port}")
            else:
                print(f"Blind partial failed from {port}")
        
        if len(partial_sigs) < self.threshold:
            print("Not enough blind partials")
            return None
        
        # Combine blind signatures
        combine_req = {
            'type': 'combine_blind',
            'partial_signatures': partial_sigs,
            'messages': messages,
            'public_info': public_info,
            'private_info': private_info,
            'blinding_nonce_e': blinding_nonce_e,
            'blinding_nonce_s': blinding_nonce_s
        }
        
        # Try first working server for combine
        for port in working_ports:
            print(f"Combining blind sig at {port}")
            resp = self.send_req(port, combine_req)
            
            if resp and resp.get('success'):
                blind_sig = resp.get('signature')
                
                if blind_sig and 'A' in blind_sig:
                    try:
                        from bbs.curve import BilinearGroup
                        g = BilinearGroup()
                        A = g.deserialize_g1_point(blind_sig['A'])
                        blind_sig['A'] = A
                        
                        print("Blind signature ready")
                        return blind_sig
                        
                    except Exception as e:
                        print(f"Blind sig deserialize failed: {e}")
                        continue
        
        print("Blind combine failed")
        return None

     # test formal blind signature
    def test_formal_blind_signature(self, messages, public_info, private_info):

        if not self.pk:
            print("Not initialized")
            return None
            
        print(f"Testing FORMAL blind signature...")
        print(f"Messages: {messages}")
        print(f"Public info: {public_info}")
        print(f"Private info: {private_info}")
        
        # Create formal blind signing request
        formal_blind_req = {
            'type': 'formal_blind_sign',
            'messages': messages,
            'public_info': public_info,
            'private_info': private_info
        }
        
        # Try to get formal blind signature from any working server
        for port in self.ports:
            print(f"Getting formal blind sig from {port}")
            resp = self.send_req(port, formal_blind_req)
            
            if resp and resp.get('success'):
                formal_blind_sig = resp.get('signature')
                
                if formal_blind_sig and 'A' in formal_blind_sig:
                    try:
                        g = BilinearGroup()
                        A = g.deserialize_g1_point(formal_blind_sig['A'])
                        formal_blind_sig['A'] = A
                        
                        print("Formal blind signature ready")
                        return formal_blind_sig
                        
                    except Exception as e:
                        print(f"Formal blind sig deserialize failed: {e}")
                        continue
            else:
                print(f"Formal blind failed from {port}")
        
        print("Formal blind combine failed")
        return None


def main():
    ports = [8001, 8002, 8003, 8004]
    threshold = 3
    messages = [111, 222, 333]

    print("BBS+ Threshold Signature Test")
    print(f"Ports: {ports}, Threshold: {threshold}, Messages: {messages}")
    
    client = BBSClient(ports, threshold)
    
    try:
        # Step 1
        print("\n--- Init ---")
        if not client.init_system(len(messages)):
            print("Init failed")
            return
        
        # Step 2  
        print("\n--- Sign ---")
        sig = client.sign(messages)
        if not sig:
            print("Sign failed")
            return
        
        # Step 3
        print("\n--- Verify ---")
        valid = client.verify(messages, sig)

        # Step 4 - Blind signature test
        print("\n--- Blind Signature Test ---")
        public_info = [111]  # public part of message
        private_info = [222, 333]  # private part that gets blinded
        all_messages = public_info + private_info  # combine for blind signing
        
        blind_sig = client.test_blind_signature(all_messages, public_info, private_info)
        print(f"blind_sig: {blind_sig}")
        if blind_sig:
            print("Blind signature generated")
            # Verify the blind signature
            client.verify(all_messages, blind_sig)

        else:
            print("Blind signature failed")

        # Step 5 - Formal blind signature test
        print("\n--- Formal Blind Signature Test ---")
        formal_blind_sig = client.test_formal_blind_signature(all_messages, public_info, private_info)
        print(f"formal_blind_sig: {formal_blind_sig}" )
        if formal_blind_sig:
            print("Formal blind signature generated")
            # Verify the formal blind signature
            client.verify(all_messages, formal_blind_sig)

        else:
            print("Formal blind signature failed")

        print(f"\n--- Result ---")
        if valid:
            print("Threshold signature worked")
        else:
            print("Threshold signature failed")

    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()