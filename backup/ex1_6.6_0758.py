# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, 206073488


# Import hashlib, base64 and cryptography as instructed.
import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# Set global maximum digest (256 bits are 1)
max_digest = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff


# Define simple hash function that gets a stringed value x and return the hash of x.
def hash(x):
    return hashlib.sha256(x.encode()).hexdigest()


# This function save all the leaves rooted in the given node and save them in the given array as Node data-type.
def create_array_of_leaves(node, array):
    if (not node):
        return
    if (not node.left and not node.right):
        array.append(node)
        return
    if node.left:
        create_array_of_leaves(node.left, array)
    if node.right:
        create_array_of_leaves(node.right, array)


# This function help SMT's node to get its value even if one of its child is None.
def set_inner_value(node, level_zero_hash):
    
    # If the left node exists, take its hash, else all of the nodes under it are zeros.
    if node.left is None:
        left = level_zero_hash
    else:
        left = node.left.hash
        
    # Same fot right node.
    if node.right is None:
        right = level_zero_hash
    else:
        right = node.right.hash
    
    # Safely return a concatenated hash as inner node value.
    return left + right


# Display Tree by in-order scan and print.
def display(node):
    if node.left is not None:
        display(node.left)
    print('value: ' + node.value[0:15] + ' hash: ' + node.hash[0:15])
    if node.right is not None:
        display(node.right)


# This function keep reading user's input until its length is 0.
def sequential_input(start_string):
    if start_string != None and start_string != '':
        result = start_string + '\n'
    line = input()
    while (len(line) > 0):
        result += line + '\n'
        line = input()
    return result[:-1]


# Define a leaf with value and hash fields.
class Leaf:
    def __init__(self, value):
        self.value = value
        self.hash = hash(value)


# Define a node with value, hash, parent and children.
class Node:
    
    # Node constructor.
    def __init__(self, value):
        self.value = value
        self.hash = hash(value)
        self.parent = None
        self.left = None
        self.right = None
        self.mark = None
        
    # This function return the other child of its parent.
    def brother(self):
        if self.parent is None:
            return None
        if self.parent.left == self:
            return self.parent.right
        if self.parent.right == self:
            return self.parent.left
        return None


class SparseNode:
    
    # SparseNode constructor.
    def __init__(self):
        self.index = None
        self.value = '1'
        self.hash = None
        self.parent = None
        self.left = None
        self.right = None
        
    # This function return the other child of its parent.
    def brother(self):
        if self.parent is None:
            return None
        if self.parent.left == self and self.parent.right is not None:
            return self.parent.right
        if self.parent.right == self and self.parent.left is not None:
            return self.parent.left
        else:
            return None 

# Define a Merkle Tree class:
class MerkleTree:

    # Merkle Tree constructor.
    def __init__(self):
        self.root = None
        self.leaves = []
        self.size = 0
    
    # Task 1 - add leaf.
    def add_leaf(self, value):
        self.leaves.append(Leaf(value))
        self.size += 1
        
    # Task 2 - calculate root hash.
    def calculate_root_hash(self):
        
        # If there are no leaves yes, return empty string.
        if len(self.leaves) == 0:
            return ''
        
        # Else, for each leave, create a node with the leave's value.
        nodes = []
        for leaf in self.leaves:
            nodes.append(Node(leaf.value))

        # Build a Merkele Tree and return the hash of its root.
        while len(nodes) > 1:
            temp = []
            for i in range(0, len(nodes), 2):
                left = nodes[i]
                left.mark = '1'
                if i + 1 < len(nodes):
                    right = nodes[i + 1]
                    right.mark = '0'
                else:
                    temp.append(nodes[i])
                    break
                parent = Node(left.hash + right.hash)
                parent.left = left
                parent.right = right
                left.parent = parent
                right.parent = parent
                temp.append(parent)
            nodes = temp
        self.root = nodes[0]
        return nodes[0].hash
    
    # Task 3 - create a proof of inclusion.
    def create_proof(self, x):
        
        # Parse given x index.
        try:
            x = int(x)   
        except:
            print()
            return

        # Get root's hash (create part A).
        proof = self.calculate_root_hash() + ' '
        
        # Create an array of nodes correspondent to the leaves.
        realLeaves = []
        create_array_of_leaves(self.root, realLeaves)

        # Find the leaf.
        try:
            node = realLeaves[x]   
        except:
            print()
            return        
        
        # Concatenate sub-proofs (create part B).
        while (node != self.root):
            proof += node.mark + node.brother().hash + ' '
            node = node.parent

        # Return proof.
        return proof[:-1]

    # Task 4 - check proof of inclusion.
    def check_proof(self, data, proof):

        # If data is not exists, return an empty string.
        try:
            me = self.check_data_exist(data)
        except:
            return ''
        
        # Else, create a proof and check if it is equal to the given proof. If so, return True, else return False.
        if (self.create_proof(me) == proof):
            return True
        else:
            return False

    # Task 4 helper function: checks if data exist at leaves array
    def check_data_exist(self, data):
        index = 0
        for leave in self.leaves:
            if (leave.value == data):
                return index
            index += 1
        else:
            raise Exception ("no data exist")

    # Task 5 - create public and private keys using RSA
    def create_keys(self):
        
        # Creating a secret key using a common exponent, key size and backend library.
        private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())

        # Store secret key in pems (a return value).
        pems = private_key.private_bytes(encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            ).decode() 
        
        # Add line-break.
        pems += '\n'
        
        # Create a public key using the secret key.
        public_key = private_key.public_key()

        # Print secret key. 
        pems += public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        
        # Return keys' pems.
        return pems
        
    # Task 6 - creating a Signed Tree Hash.
    def create_STH(self, skey):
        
        # Load pem private key with no password and with default backend.
        skey = load_pem_private_key(skey.encode(), password = None, backend = default_backend())
        signature = skey.sign(self.root.hash.encode(),
                padding.PSS(mgf = padding.MGF1(hashes.SHA256()),
                        salt_length = padding.PSS.MAX_LENGTH
                    ),
                hashes.SHA256()
            )
        
        # Convert signature to base64, decode it, and return it.
        return base64.b64encode(signature).decode()
        
    # Task 7 - verifing a signature.
    def verify_signature(self, pkey, signature, text):
        
        # Load pem public key with default backend.
        pkey = load_pem_public_key(pkey.encode(), backend = default_backend())
        
        # If pkey cannot be verified, verify() function throws exception.
        try:
            pkey.verify(base64.decodebytes(signature.encode()), text.encode(),
                    padding.PSS(
                        mgf = padding.MGF1(hashes.SHA256()),
                        salt_length = padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            return True
        except:
            return False


# A theoretical full Merkle Tree where all of its leaves holds a value of zero, have one hash for each depth-level.
# The following zero_hashes array maps between tree depth (index) to a hash.
zero_hashes = []
zero_hashes.append('0')
for i in range(256):
    zero_hashes.append(hash(zero_hashes[i] + zero_hashes[i]))
zero_hashes = zero_hashes[::-1]


# Define a Sparse Merkle Tree class:
class SparseMerkleTree:
    
    # Sparse Merkle Tree constructor.
    def __init__(self):
        self.root = SparseNode()
        self.root.hash = zero_hashes[0]
        self.marked_leaves = []
        self.left_all_zeros = 1
        self.right_all_zeros = 1

    # Task 8 - mark a leaf.
    def mark_leaf(self, digest):
        
        # Use the digest as indes and turn the digest into a binary string.
        index = int(digest, 16)
        index_b = bin(index)[2:].zfill(256)
        
        # Check the side of the leaf.
        if index < max_digest // 2:
            self.left_all_zeros = 0
        else:
            self.right_all_zeros = 0
        
        # Find leaf's location and for each '1' in index_b, turn right, for each '0', turn left.
        node = self.root
        for bit in index_b:
            if bit == '1':
                if node.right is None:
                    node.right = SparseNode()
                    node.right.parent = node
                node = node.right
            elif bit == '0':
                if node.left is None:
                    node.left = SparseNode()
                    node.left.parent = node
                node = node.left

        # Set leaf index and hash, and add it to the marked leaves array.
        node.index = index
        node.hash = '1'
        self.marked_leaves.append(node)

        # Recalculate hashes of nodes in the path, from the leaf to the root.
        depth = 256
        while (depth > 0):
            node = node.parent
            node.value = set_inner_value(node, zero_hashes[depth])
            node.hash = hash(node.value)
            depth -= 1
            
    # Task 9 - calculate root hash.
    def calculate_root_hash(self):
        return self.root.hash
        
    # Task 10 - create a proof of inclusion.
    def create_proof(self, digest):
        
        # Get root's hash (create part A).
        proof = self.calculate_root_hash() + ' '
        
        # If there are nor marked leaves part B is root's hash.
        if len(self.marked_leaves) == 0:
            proof += self.root.hash
            return proof
        
        # Convert deigest to index.
        index = int(digest, 16)
        
        # Look for the leaf in the marked-leaves array.
        node = None
        for leaf in self.marked_leaves:
            if leaf.index == index:
                node = leaf
                break
        
        # If the leaf is found, concatenate sub-proofs (create part B) and return proof.
        if node != None:
            depth = 256
            while (depth > 0):
                if node.brother() is None:
                    proof += zero_hashes[depth] + ' '
                else:
                    proof += node.brother().hash + ' '
                node = node.parent
                depth -= 1
            return proof[:-1]
        
        # Else, the leaf is unmarked.
        index_b = bin(index)[2:].zfill(256)
        
        # Find leaf's location and for each '1' in index_b, turn right, for each '0', turn left.
        node = self.root
        for bit in index_b:
            if bit == '1':
                if node.right is None:
                    node.right = SparseNode()
                    node.right.parent = node
                node = node.right
            elif bit == '0':
                if node.left is None:
                    node.left = SparseNode()
                    node.left.parent = node
                node = node.left

        # Set leaf index and hash, and add it to the marked leaves array.
        node.index = index
        node.hash = '0'
        node_c = node

        # Recalculate hashes of nodes in the path, from the leaf to the root.
        depth = 256
        while (depth > 0):
            node_c = node_c.parent
            node_c.value = set_inner_value(node_c, zero_hashes[depth])
            node_c.hash = hash(node_c.value)
            depth -= 1
        
        # Special case 1 - the leaf is in the left side where all the leaves in the left are zeros.
        if self.left_all_zeros:
            return proof + zero_hashes[1] + ' ' + self.root.right.hash
        
        # Special case 2 - the leaf is in the right side where all the leaves in the right are zeros.
        if self.right_all_zeros:
            return proof + zero_hashes[1] + ' ' + self.root.left.hash
        
        # In any other case, calculate hashes like in a regular Merkle Tree.
        depth = 256
        while (depth > 0):
            if node.brother() is None:
                proof += zero_hashes[depth] + ' '
            else:
                proof += node.brother().hash + ' '
            node = node.parent
            depth -= 1
        return proof[:-1]
        
    # Task 11 - check proof of inclusion.
    def check_proof(self, digest, classification, proof):
        if classification == '0':
            check = self.create_proof(digest)
        elif classification == '1':
            self.mark_leaf(digest)
            check = self.create_proof(digest)
            self.marked_leaves.pop()
        if (check == proof):
            return True
        else:
            return False
        

# The 'main':

# Create instances of a MerkleTree and a SparseMerkleTree.
mt = MerkleTree()
smt = SparseMerkleTree()

# Program's main loop.
while (1):
    
    # Get th command and the arguments from the user.
    command = input().split(' ', 1)
    task = command[0]
    if len(command) == 2:
        args = command[1]

    ##### Merkle Tree Tasks #####

    # Task 1 - Add a leaf. No output.
    if (task == '1'):
        mt.add_leaf(args)
            
    # Task 2 - Calculate root's hash. Ignore addtional arguments.
    elif (task == '2'):
        print(mt.calculate_root_hash())
    
    # Task 3 - Create proof of inclusion.
    elif (task == '3'):
        print(mt.create_proof(args))

    # Task 4 - Check proof of inclusion.
    elif (task == '4'):
        args = args.split(' ', 1)
        print(mt.check_proof(args[0], args[1]))

    # Task 5 - Create private and public keys with RSA.
    elif (task == '5'):
        print(mt.create_keys())
        
    # Task 6 - Create a signature of the current tree root.
    elif (task == '6'):
        skey = sequential_input(args)
        print(mt.create_STH(skey))
        
    # Task 7 - Signature verification.
    elif (task == '7'):
        pkey = sequential_input(args)
        additional_input = input()
        while (additional_input == ''):
            additional_input = input()
        additional_input = additional_input.split(' ')
        signature = additional_input[0]
        text = additional_input[1]
        print(mt.verify_signature(pkey, signature, text))
    
    ##### Sparse Merkle Tree Tasks #####

    # Task 8 - Mark a leaf.
    elif (task == '8'):
        smt.mark_leaf(args)
    
    # Task 9 - Calculate root hash (sparse).    
    elif (task == '9'):
        print(smt.calculate_root_hash())
        
    # Task 10 - Create proof of inclusion (sparse).
    elif (task == '10'):
        print(smt.create_proof(args))
        
    # Task 11 - Check proof of inclusion (sparse).
    elif (task == '11'):
        args = args.split(' ')
        proof = args[2]
        i = 3
        while (i < len(args)):
            proof += ' ' + args[i]
            i += 1
        print(smt.check_proof(args[0], args[1], proof))
        
    ##### Displayers #####
    
    # Display Merkle Tree.
    elif (task == '0'):
        display(mt.root)
        
    # Display Sparse Merkle Tree.  
    elif (task == '-1'):
        display(smt.root)