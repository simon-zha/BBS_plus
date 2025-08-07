#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bbs.threshold import ThresholdBBSPlus, FormalThresholdBBSPlus
from bbs.bbs_plus import BBSPlus
import json
import socket
import threading
import hashlib
import random
import secrets
import argparse


class BBSServer:
    def __init__(self, server_id, n, t, port):
        self.id = server_id
        self.n = n
        self.t = t
        self.port = port
        self.threshold_bbs = ThresholdBBSPlus(n, t)
        self.formal_threshold_bbs = FormalThresholdBBSPlus(n, t)  # For blind signature
        self.setup_data = None # store global public keys and shares
        self.my_share = None  # store current node shares

    def setup(self, msg_len):
        # Make sure all servers generate the same setup
        # Simple version for testing
        seed = hashlib.sha256(f"bbs_setup_{msg_len}_{self.n}_{self.t}".encode()).digest()
        random.seed(int.from_bytes(seed[:4], 'big'))
        old_randbelow = secrets.randbelow
        secrets.randbelow = lambda n: random.randrange(n)

        # get public keys and shares
        self.setup_data = self.threshold_bbs.setup(msg_len)
        secrets.randbelow = old_randbelow
        
        # Find my key share
        for share in self.setup_data['key_shares']:
            if share[0] == self.id:
                self.my_share = share
                break
        
        if not self.my_share:
            print(f"No key share for server {self.id}")
            return
        
        print(f"Server {self.id} setup done")
        return self.setup_data['public_key']

    # generate partial signatures
    def partial_sign(self, messages):
        if not self.setup_data:
            #raise Exception("Not initialized")
            print("Not initialized")
            return
        
        # Generate global params from messages
        msg_hash = hashlib.sha256(str(messages).encode()).digest()
        e_hash = hashlib.sha256(msg_hash + b"_e").digest()
        s_hash = hashlib.sha256(msg_hash + b"_s").digest()
        
        global_e = int.from_bytes(e_hash, 'big') % self.threshold_bbs.group.q
        global_s = int.from_bytes(s_hash, 'big') % self.threshold_bbs.group.q
        
        party_id, key_val = self.my_share
        return {
            'party_id': party_id,
            'key_share_value': key_val,
            'e': global_e,
            's': global_s
        }

    # collet at least t partial signatures then combine to final signature {A,e,s}
    def combine_sigs(self, partial_sigs, messages):

        # Reconstruct the key
        shares = [(sig['party_id'], sig['key_share_value']) for sig in partial_sigs]
        secret_key = self.threshold_bbs.shamir.reconstruct_secret(shares)
        
        # Sign with reconstructed key
        global_e = partial_sigs[0]['e']
        global_s = partial_sigs[0]['s']
        H = self.setup_data['public_key']['H']
        
        bbs = BBSPlus()
        sig = bbs.sign_with_params(secret_key, messages, H, global_e, global_s)
        
        # Quick verification
        if not bbs.verify(self.setup_data['public_key'], messages, sig):
            print("bad signature")
            return
        
        print(f"Server {self.id} combined signature")
        return sig

    # Generate partial blind signature
    def partial_blind_sign(self, messages, public_info, private_info, blinding_nonce_e, blinding_nonce_s):

        print(f"Server {self.id} blind signing")
        
        # For simplified blind signing, just use the same approach as regular partial signing
        # The actual blinding would happen in the formal protocol
        msg_hash = hashlib.sha256(str(messages + public_info + private_info).encode()).digest()
        e_hash = hashlib.sha256(msg_hash + b"_blind_e").digest()
        s_hash = hashlib.sha256(msg_hash + b"_blind_s").digest()
        
        global_e = int.from_bytes(e_hash, 'big') % self.threshold_bbs.group.q
        global_s = int.from_bytes(s_hash, 'big') % self.threshold_bbs.group.q
        
        party_id, key_val = self.my_share
        partial_blind_signature = {
            'party_id': party_id,
            'key_share_value': key_val,
            'e': global_e,
            's': global_s,
            'blinding_nonce_e': blinding_nonce_e,
            'blinding_nonce_s': blinding_nonce_s,
            'public_info': public_info,
            'private_info': private_info
        }
        return partial_blind_signature

    # Combine partial blind signatures into final blind signature
    def combine_blind_sigs(self, partial_sigs, messages, public_info, private_info, blinding_nonce_e, blinding_nonce_s):

        print(f"Server {self.id} combining blind signatures")
        
        # Reconstruct the key from partial signatures
        shares = [(sig['party_id'], sig['key_share_value']) for sig in partial_sigs]
        secret_key = self.threshold_bbs.shamir.reconstruct_secret(shares)
        
        # Use global parameters from first partial signature
        global_e = partial_sigs[0]['e']
        global_s = partial_sigs[0]['s']
        H = self.setup_data['public_key']['H']
        
        # Create blind signature using reconstructed key
        bbs = BBSPlus()
        blind_sig = bbs.sign_with_params(secret_key, messages, H, global_e, global_s)
        
        # Simple version for unblinding simulation
        print(f"Server {self.id} unblinding signature with blinding_nonce_e={blinding_nonce_e}, blinding_nonce_s={blinding_nonce_s}")
        
        # Verify the blind signature
        if not bbs.verify(self.setup_data['public_key'], messages, blind_sig):
            print("bad blind signature")
            return
        
        print(f"Server {self.id} combined blind signature")
        return blind_sig

    # Use the formal threshold blind signature implementation
    def formal_blind_sign(self, messages, public_info, private_info):
        print(f"Server {self.id} formal blind signing")
        
        # Prepare setup_data with message_count for FormalThresholdBBSPlus
        formal_setup_data = {
            'public_key': self.setup_data['public_key'],
            'key_shares': self.setup_data['key_shares'],
            'global_private_key': self.setup_data.get('global_private_key'),
            'message_count': len(messages)  # Add the missing message_count
        }
        
        self.formal_threshold_bbs.setup_data = formal_setup_data
        
        # Use threshold number of parties for blind signing
        selected_parties = list(range(1, self.t + 1))  # Only need threshold parties
        
        try:
            # Call the formal blind threshold signature
            blind_signature = self.formal_threshold_bbs.blind_threshold_sign(
                f"client_{self.id}", messages, selected_parties, public_info, private_info
            )
            
            print(f"Server {self.id} formal blind signature generated")
            return blind_signature
            
        except Exception as e:
            print(f"Server {self.id} formal blind sign error: {e}")
            raise e

    def handle_request(self, client_sock):
        try:
            data = client_sock.recv(8192).decode('utf-8')
            if not data:
                return
                
            req = json.loads(data)
            req_type = req.get('type')
            
            print(f"Server {self.id}: {req_type}")

            if req_type == 'setup':
                msg_len = req['message_length']
                pk = self.setup(msg_len)

                # Serialize public key
                H_strs = [self.threshold_bbs.group.serialize_g1_point(h) for h in pk['H']]
                X_str = self.threshold_bbs.group.serialize_g2_point(pk['X'])

                resp = {
                    'success': True,
                    'server_id': self.id,
                    'public_key': {'X': X_str, 'H': H_strs}
                }

            elif req_type == 'sign':
                messages = req['messages']
                partial_sig = self.partial_sign(messages)
                resp = {
                    'success': True,
                    'server_id': self.id,
                    'partial_signature': partial_sig
                }

            elif req_type == 'combine':
                partial_sigs = req['partial_signatures']
                messages = req['messages']
                final_sig = self.combine_sigs(partial_sigs, messages)
                
                resp = {
                    'success': True,
                    'server_id': self.id,
                    'signature': {
                        'A': self.threshold_bbs.group.serialize_g1_point(final_sig['A']),
                        'e': final_sig['e'],
                        's': final_sig['s']
                    }
                }

            elif req_type == 'blind_sign':
                messages = req['messages']
                public_info = req.get('public_info', [])
                private_info = req.get('private_info', [])
                blinding_nonce_e = req.get('blinding_nonce_e', 0)
                blinding_nonce_s = req.get('blinding_nonce_s', 0)
                
                partial_sig = self.partial_blind_sign(messages, public_info, private_info, blinding_nonce_e, blinding_nonce_s)
                resp = {
                    'success': True,
                    'server_id': self.id,
                    'partial_signature': partial_sig
                }

            elif req_type == 'combine_blind':
                partial_sigs = req['partial_signatures']
                messages = req['messages']
                public_info = req.get('public_info', [])
                private_info = req.get('private_info', [])
                blinding_nonce_e = req.get('blinding_nonce_e', 0)
                blinding_nonce_s = req.get('blinding_nonce_s', 0)
                
                final_sig = self.combine_blind_sigs(partial_sigs, messages, public_info, private_info, blinding_nonce_e, blinding_nonce_s)
                
                resp = {
                    'success': True,
                    'server_id': self.id,
                    'signature': {
                        'A': self.threshold_bbs.group.serialize_g1_point(final_sig['A']),
                        'e': final_sig['e'],
                        's': final_sig['s']
                    }
                }

            elif req_type == 'formal_blind_sign':
                messages = req['messages']
                public_info = req.get('public_info', [])
                private_info = req.get('private_info', [])
                
                blind_sig = self.formal_blind_sign(messages, public_info, private_info)
                
                resp = {
                    'success': True,
                    'server_id': self.id,
                    'signature': {
                        'A': self.threshold_bbs.group.serialize_g1_point(blind_sig['A']),
                        'e': blind_sig['e'],
                        's': blind_sig['s']
                    }
                }

            else:
                resp = {'success': False, 'message': f'Unknown: {req_type}'}
            
            client_sock.send(json.dumps(resp).encode('utf-8'))
            
        except Exception as e:
            print(f"Server {self.id} error: {e}")
            err_resp = {'success': False, 'message': str(e)}
            try:
                client_sock.send(json.dumps(err_resp).encode('utf-8'))
            except:
                pass
        finally:
            client_sock.close()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('localhost', self.port))
        sock.listen(5)
        
        print(f"Server {self.id} listening on {self.port}")
        
        try:
            while True:
                client_sock, addr = sock.accept()
                # Handle in thread
                t = threading.Thread(target=self.handle_request, args=(client_sock,))
                t.daemon = True
                t.start()
                
        except KeyboardInterrupt:
             print(f"Server {self.id} stopping")
        finally:
             sock.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', type=int, required=True)
    parser.add_argument('--n', type=int, default=4)
    parser.add_argument('--t', type=int, default=3)
    parser.add_argument('--port', type=int, required=True)
    
    args = parser.parse_args()
    
    server = BBSServer(args.id, args.n, args.t, args.port)
    #server = BBSServer(args.id, args.port)
    server.run()