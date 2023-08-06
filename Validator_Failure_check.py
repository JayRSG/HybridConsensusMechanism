import hashlib
import time
import random
import os
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json

class ValidatorNode:
    def __init__(self, name):
        self.name = name
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.voting_data = []

    def respond_to_challenge(self, challenge_type, challenge_data):
        # Respond based on the type of challenge
        if challenge_type == "mathematical":
            return str(eval(challenge_data))
        elif challenge_type == "string_manipulation":
            return challenge_data[::-1]
        elif challenge_type == "hash":
            return hashlib.sha256(challenge_data.encode()).hexdigest()
        elif challenge_type == "time":
            return str(int(time.time()))
        elif challenge_type == "cryptographic_signature":
            message = SHA256.new(bytes.fromhex(challenge_data))
            signature = pkcs1_15.new(self.private_key).sign(message)
            return signature.hex()

validators = {
    "Alice": ValidatorNode("Alice"),
    "Bob": ValidatorNode("Bob"),
    "Charlie": ValidatorNode("Charlie"),
    "Dave": ValidatorNode("Dave"),
    "Eve": ValidatorNode("Eve")
}

def mathematical_challenge():
    a, b = random.randint(1, 100), random.randint(1, 100)
    return "mathematical", f"{a}+{b}", str(a+b)

def string_manipulation_challenge():
    s = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=10))
    return "string_manipulation", s, s[::-1]

def hash_challenge():
    challenge_str = str(random.randint(1, 10000))
    return "hash", challenge_str, hashlib.sha256(challenge_str.encode()).hexdigest()

def time_challenge():
    return "time", "current_time", str(int(time.time()))

def cryptographic_signature_challenge(validator_node):
    message = os.urandom(32).hex()
    message_hash = SHA256.new(bytes.fromhex(message))
    signature = pkcs1_15.new(validator_node.private_key).sign(message_hash)
    # Return the challenge type, challenge data, and the expected response (the signature)
    return ("cryptographic_signature", message, signature.hex())


CHALLENGE_FUNCTIONS = [
    mathematical_challenge,
    string_manipulation_challenge,
    hash_challenge,
    time_challenge,
    cryptographic_signature_challenge
]

def generate_all_challenges(validator_node):
    # Generate all types of challenges for a given validator
    return [func(validator_node) if func in [cryptographic_signature_challenge] 
            else func() for func in CHALLENGE_FUNCTIONS]

def detect_compromised(validators_data):
    # Detect validators that have a suspiciously high failure or success rate
    potentially_compromised = []
    for validator, votes in validators_data.items():
        in_favor = votes.count(1)
        against = votes.count(0)

        if (in_favor / len(votes) < 0.7) or (against / len(votes) > 0.7):
            potentially_compromised.append(validator)
    return potentially_compromised

for validator, node in validators.items():
    all_challenges = generate_all_challenges(node)
    for challenge_type, challenge, expected_response in all_challenges:
        response = node.respond_to_challenge(challenge_type, challenge)
        
        # Simulating Eve failing the challenges
        if validator == "Eve":
            if challenge_type == "mathematical":
                response = str(int(response) + 1)  # adding 1 to the result
            elif challenge_type == "string_manipulation":
                response += "x"  # add an extra letter at the end
            elif challenge_type == "hash":
                response += "x"
            elif challenge_type == "time":
                response = str(int(response) + 1000)  # adding an offset to the time
            elif challenge_type == "cryptographic_signature":
                response = response[:-1] + 'x'  # modify the last character of the signature
            
        # Record the outcome of the challenge
        node.voting_data.append(1 if str(response) == str(expected_response) else 0)
        
        print(node.voting_data)
        print(f"{validator} - Challenge: {challenge_type}, Response: {response}, Expected: {expected_response}")

# Detect and print potentially compromised validators
compromised_validators = detect_compromised({validator: node.voting_data for validator, node in validators.items()})
print("Potentially compromised validators:", compromised_validators)

# Save potentially compromised validators to a file
with open('compromised_validators.json', 'w') as file:
    json.dump(compromised_validators, file)