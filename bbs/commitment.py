# This file implements a "multi-party commitment and disclosure" function.
# Multiple participants can first make a commitment to a certain value, and then reveal this value in the subsequent stage.
# At the same time, others can verify whether the previous commitment and the currently disclosed value are consistent.

import hashlib
import secrets
from typing import Dict, Optional, Any


# Functionality 3.2 FCom
class FCom:

    def __init__(self):
        self.commitments = {}
        self.commitment_strings = {}

    # Functionality 3.2 FCom.commit
    def commit(self, sid, committer, parties, value):

        if sid in self.commitments:
            return None
        
        salt = secrets.token_bytes(32)
        
        value_bytes = str(value).encode('utf-8')
        commitment_hash = hashlib.sha256(value_bytes + salt).hexdigest()
        
        self.commitments[sid] = {
            'committer': committer,
            'parties': parties,
            'value': value,
            'salt': salt,
            'committed': True,
            'decommitted': False
        }
        
        self.commitment_strings[sid] = commitment_hash
        
        return commitment_hash


    # Functionality 3.2 FCom.decommit
    def decommit(self, sid):

        if sid not in self.commitments:
            return None
        
        commitment_data = self.commitments[sid]
        if not commitment_data['committed'] or commitment_data['decommitted']:
            return None
        
        commitment_data['decommitted'] = True
        
        return commitment_data['value'], commitment_data['salt']
    

    # Functionality 3.2 FCom.verify
    def verify_commitment(self, sid, value, salt, commitment_string):

        value_bytes = str(value).encode('utf-8')
        computed_hash = hashlib.sha256(value_bytes + salt).hexdigest()
        
        return computed_hash == commitment_string
    

    def get_commitment(self, sid):
        return self.commitment_strings.get(sid)
    
    def is_committed(self, sid):
        return sid in self.commitments and self.commitments[sid]['committed']
    
    def is_decommitted(self, sid):
        return sid in self.commitments and self.commitments[sid]['decommitted']

'''
CommitmentManager
- Used for managing commitments and cancellations among multiple participants
- Allows sending and receiving information about commitments and cancellations
- Batch retrieval of all participants' commitment values
- Checks whether all participants have made commitments or withdrawn their commitments
'''
class CommitmentManager:

    def __init__(self, party_id):
        self.party_id = party_id
        self.fcom = FCom()
        self.received_commitments = {}
        self.received_decommitments = {} 
    
    def send_commitment(self, sid, parties, value):
        commitment = self.fcom.commit(sid, self.party_id, parties, value)
        return commitment
    
    def receive_commitment(self, sid, from_party, commitment_string):
        key = (sid, from_party)
        self.received_commitments[key] = commitment_string
    
    def send_decommitment(self, sid):
        result = self.fcom.decommit(sid)
        return result
    
    def receive_decommitment(self, sid, from_party, value, salt):
        key = (sid, from_party)
        
        if key in self.received_commitments:
            commitment_string = self.received_commitments[key]
            if self.fcom.verify_commitment(sid, value, salt, commitment_string):
                self.received_decommitments[key] = (value, salt)
                return True
        return False
    
    def get_all_decommitted_values(self, sid, expected_parties):
        values = {}
        
        for party in expected_parties:
            key = (sid, party)
            if key in self.received_decommitments:
                value, salt = self.received_decommitments[key]
                values[party] = value
        return values
    
    def check_all_committed(self, sid, expected_parties):
        for party in expected_parties:
            key = (sid, party)
            if key not in self.received_commitments:
                return False
        return True
    
    def check_all_decommitted(self, sid, expected_parties):
        for party in expected_parties:
            key = (sid, party)
            if key not in self.received_decommitments:
                return False
        return True 