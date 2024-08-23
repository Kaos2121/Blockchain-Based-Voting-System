import hashlib
import json
import time
import os
from flask import Flask, jsonify, request, abort
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from urllib.parse import urlparse
import asyncio
import aiohttp
import logging
from dotenv import load_dotenv
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables
load_dotenv()
AES_KEY = os.getenv('AES_KEY', get_random_bytes(16))  # Load AES key securely

# Initialize logging
logging.basicConfig(filename='blockchain.log', level=logging.INFO, format='%(asctime)s - %(message)s')

class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_votes = []
        self.nodes = set()

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        encrypted_votes = self.encrypt_data(json.dumps(self.current_votes).encode())

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'votes': encrypted_votes.hex(),
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Reset the current list of votes
        self.current_votes = []

        self.chain.append(block)
        logging.info(f'New block created: {block}')
        return block

    def new_vote(self, voter_id, candidate, signature, nonce, timestamp):
        """
        Creates a new vote to go into the next mined Block
        :param voter_id: Address of the voter
        :param candidate: Candidate for whom the vote is cast
        :param signature: Digital signature of the vote
        :param nonce: Unique identifier to prevent replay attacks
        :param timestamp: Timestamp of the vote
        :return: The index of the Block that will hold this vote
        """
        vote = {
            'voter_id': voter_id,
            'candidate': candidate,
            'nonce': nonce,
            'timestamp': timestamp
        }

        if not self.verify_signature(voter_id, json.dumps(vote), signature):
            abort(400, "Invalid signature")

        # Additional check to prevent replay attacks
        if any(v['nonce'] == nonce for v in self.current_votes):
            abort(400, "Replay attack detected")

        self.current_votes.append(vote)
        logging.info(f'New vote added: {vote}')
        return self.last_block['index'] + 1

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        :return: <str> hash
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm with dynamic difficulty:
        - Find a number p' such that hash(pp') contains leading 4 zeroes
        - p is the previous proof, and p' is the new proof
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        start_time = time.time()
        while self.valid_proof(last_proof, proof) is False:
            proof += 1
        mining_time = time.time() - start_time

        # Adjust difficulty based on mining time
        if mining_time < 10:
            self.difficulty += 1
        elif mining_time > 30 and self.difficulty > 1:
            self.difficulty -= 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, difficulty=4):
        """
        Validates the Proof: Does hash(last_proof, proof) contain leading zeroes?
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :param difficulty: <int> Difficulty level
        :return: <bool> True if correct, False if not.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty

    def valid_chain(self, chain):
        """
        Determine if a given blockchain is valid
        :param chain: A blockchain
        :return: True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            # Check that the hash of the block is correct
            if block['previous_hash'] != self.hash(last_block):
                return False

            # Check that the Proof of Work is correct
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False

            last_block = block
            current_index += 1

        return True

    def register_node(self, address):
        """
        Add a new node to the list of nodes
        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """
        parsed_url = urlparse(address)
        self.nodes.add(parsed_url.netloc)
        logging.info(f'Node registered: {parsed_url.netloc}')

    async def resolve_conflicts(self):
        """
        This is our Consensus Algorithm, it resolves conflicts
        by replacing our chain with the longest one in the network.
        :return: True if our chain was replaced, False if not
        """
        neighbours = self.nodes
        new_chain = None

        # We're only looking for chains longer than ours
        max_length = len(self.chain)

        # Grab and verify the chains from all the nodes in our network
        async with aiohttp.ClientSession() as session:
            for node in neighbours:
                async with session.get(f'http://{node}/chain') as response:
                    if response.status == 200:
                        data = await response.json()
                        length = data['length']
                        chain = data['chain']

                        # Check if the length is longer and the chain is valid
                        if length > max_length and self.valid_chain(chain):
                            max_length = length
                            new_chain = chain

        # Replace our chain if we discovered a new, valid chain longer than ours
        if new_chain:
            self.chain = new_chain
            logging.info('Chain replaced with a longer valid chain.')
            return True

        logging.info('Our chain is authoritative.')
        return False

    @staticmethod
    def generate_keys():
        """
        Generates a pair of RSA keys (private and public)
        :return: RSA key pair
        """
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        return private_key, public_key

    @staticmethod
    def sign_data(private_key, data):
        """
        Sign data using RSA private key
        :param private_key: RSA private key
        :param data: Data to be signed
        :return: Digital signature
        """
        key = RSA.import_key(private_key)
        h = SHA256.new(data.encode())
        signature = pkcs1_15.new(key).sign(h)
        return signature

    @staticmethod
    def verify_signature(public_key, data, signature):
        """
        Verify a digital signature using RSA public key
        :param public_key: RSA public key
        :param data: Signed data
        :param signature: Digital signature
        :return: True if signature is valid, False otherwise
        """
        key = RSA.import_key(public_key)
        h = SHA256.new(data.encode())
        try:
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False

    def encrypt_data(self, data):
        """
        Encrypts data using AES encryption
        :param data: Data to be encrypted
        :return: Encrypted data
        """
        cipher = AES.new(AES_KEY, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def decrypt_data(self, encrypted_data):
        """
        Decrypts AES encrypted data
        :param encrypted_data: Data to be decrypted
        :return: Decrypted data
        """
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        cipher = AES.new(AES_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

# Instantiate the Node
app = Flask(__name__)

# Implement rate limiting to prevent DoS attacks
limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Instantiate the Blockchain
blockchain = Blockchain()

def require_https(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.url.startswith('http://'):
            url = request.url.replace('http://', 'https://', 1)
            return jsonify({'message': 'Please use HTTPS'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/mine', methods=['GET'])
@require_https
def mine():
    # We run the proof of work algorithm to get the next proof...
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    # Forge the new Block by adding it to the chain
    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'votes': block['votes'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }
    return jsonify(response), 200

@app.route('/vote', methods=['POST'])
@limiter.limit("10 per minute")
@require_https
def new_vote():
    values = request.get_json()

    # Check that the required fields are in the POST'ed data
    required = ['voter_id', 'candidate', 'signature', 'nonce', 'timestamp']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Create a new vote
    index = blockchain.new_vote(values['voter_id'], values['candidate'], values['signature'], values['nonce'], values['timestamp'])

    response = {'message': f'Vote will be added to Block {index}'}
    return jsonify(response), 201

@app.route('/chain', methods=['GET'])
@require_https
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
@require_https
def register_nodes():
    values = request.get_json()

    nodes = values.get('nodes')
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
@require_https
async def consensus():
    replaced = await blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200

if __name__ == '__main__':
    # Enforce HTTPS in the Flask app
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
