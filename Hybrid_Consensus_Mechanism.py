from Validator_Failure_check import detect_compromised_validators

class Block:
    def __init__(self, transactions, previous_hash):
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        return hash(str(self.transactions) + str(self.previous_hash))

class HybridConsensus:
    def __init__(self):
        self.authorized_validators = set()  # Set of approved validators
        self.stakes = {}  # Dictionary to hold stakes of validators
        self.chain = [Block([], "0")]
        self.compromised = set()  # Set to track compromised validators

    def authorize_validator(self, validator):
        self.authorized_validators.add(validator)

    def set_stake(self, validator, stake):
        if validator in self.authorized_validators:
            self.stakes[validator] = stake

    def report_compromised(self):
        compromised_validators = detect_compromised_validators()
        for validator in compromised_validators:
            self.compromised.add(validator)

    def select_validator(self):
        # Ensure 2/3 of validators are not compromised
        if len(self.compromised) > len(self.authorized_validators) / 3:
            print("Network is not secure!")
            return None

        # Filter out compromised validators and sort by stake
        valid_validators = [v for v in self.authorized_validators if v not in self.compromised]
        valid_validators.sort(key=lambda v: self.stakes.get(v, 0), reverse=True)
        
        if valid_validators:
            return valid_validators[0]  # Return the validator with the highest stake

    def add_block(self, block, validator):
        if validator in self.authorized_validators and validator == self.select_validator():
            if block.previous_hash == self.chain[-1].hash:
                self.chain.append(block)
                print(f"Block {block.hash} added by validator {validator}!")
            else:
                print("Invalid block. Doesn't chain correctly.")
        else:
            print("Validator not permitted to add block at this time.")

# Example usage:

consensus = HybridConsensus()
consensus.authorize_validator("Alice")
consensus.authorize_validator("Bob")
consensus.authorize_validator("Charlie")
consensus.authorize_validator("Dave")
consensus.authorize_validator("Eve")

consensus.set_stake("Alice", 50)
consensus.set_stake("Bob", 70)
consensus.set_stake("Charlie", 40)
consensus.set_stake("Dave", 80)
consensus.set_stake("Eve", 20)

# Detect and report compromised validators
consensus.report_compromised()
print(consensus.compromised)  # Should print the set of compromised validators

block1 = Block(["tx1", "tx2", "tx3"], consensus.chain[-1].hash)
selected_validator = consensus.select_validator()
consensus.add_block(block1, selected_validator)

block2 = Block(["tx4", "tx5", "tx6"], consensus.chain[-1].hash)
selected_validator = consensus.select_validator()
consensus.add_block(block2, selected_validator)