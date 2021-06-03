# Shlomi Ben-Shushan, 311408264, Ofir Ben-Ezra, <206073488>

# Import hashlib, base64 and cryptography as instructed.
import hashlib
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# Define simple hash function.
def hash(x):
    return hashlib.sha256(x.encode('utf-8')).hexdigest()


# This function gets a number n and return True if and only if n is a power of 2.
def is_power_of_two(n):
    if (n == 0):
        return False
    while (n != 1):
        n = n / 2
        if (n % 2 != 0 and n != 1):
            return False
    return True


# Define a Node:
class Node:
    
    # Node constructor.
    def __init__(self, value):
        self.parent = None
        self.value = value
        if (value is not None):
            self.hash = hash(value)
        self.left = None
        self.right = None
    
    # This function return the other child of its parent.
    def brother(self):
        if self.parent is None:
            return None
        if self.parent.left == self:
            return self.parent.right
        if self.parent.right == self:
            return self.parent.left
        return None


# Define a Merkle Tree class:
class MerkleTree:

    # Merkle Tree constructor.
    def __init__(self):
        self.root = Node(None)
        self.size = 0
        self.leaves = []
        
    # Task 1 - add leaf
    def add_leaf(self, value):
        
        # If there is no leaves yet, replace the 'None' node with a new node with the new value.
        # Trust the Garbage-Collector to deallocate memory.
        if (self.size == 0):
            self.root = Node(value)
            self.leaves.append(self.root)
            
        # Every power-of-2 nodes, the tree sets a new root.
        elif (is_power_of_two(self.size)):
            left = self.root
            right = Node(value)
            self.leaves.append(right)
            inner = Node(left.hash + right.hash)
            left.parent = inner
            right.parent = inner
            inner.left = left
            inner.right = right
            inner.parent = None
            self.root = inner
            
        # If the addition of the node is in between 2's powers, add the node to the right of the rightest leaf.
        else:
            rightest = self.leaves[len(self.leaves) - 1]
            rightest_parent = rightest.parent
            left = rightest
            right = Node(value)
            self.leaves.append(right)
            inner = Node(left.hash + right.hash)
            inner.left = left
            inner.right = right
            left.parent = inner
            right.parent = inner
            rightest_parent.right = inner
            
        # Advance tree size by one.
        self.size += 1
        
    # Task 2 - calculate root hash
    def calculate_root_hash(self):
        if self.size != 0:
            print(self.root.hash)
        else:
            print()
            
    # Task 3 - create a proof of inclusion
    def create_POI(self, x):
        
        try:
            x = int(x)   
        except:
            print()
            return
        
        try:
            me = self.leaves[x]   
        except:
            print()
            return

        POI = self.root.hash + ' '
        while (me != self.root):
            POI = me.brother().hash + ' '
            me = me.parent

        return POI[:-1]


    # Task 4 - check proof of inclusion.
    def check_POI(self, data, proof):

        try:
            me = mt.check_data_exist(data)
        except:
            print("no such data exist")
            return
        if(mt.create_POI(me) == proof):
            print("True")
        else:
            print("False")

    # check if data exist at leaves array
    def check_data_exist(self, data):
        index = 0
        for leave in self.leaves:
            if(leave.value == data):
                return index
            index += 1
        else:
            raise Exception ("no data exist")


    # Task 5 - create public and private keys using RSA
    def create_keys(self):
        
        # Creating a secret key using a common exponent, key size and backend library.
        private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())

        # Print secret key. 
        pem = private_key.private_bytes(encoding = serialization.Encoding.PEM,
                format = serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm = serialization.NoEncryption()
            )           
        print(pem.decode())

        # Creatin a public key using the secret key.
        public_key = private_key.public_key()

        # Print secret key. 
        pem = public_key.public_bytes(
                encoding = serialization.Encoding.PEM,
                format = serialization.PublicFormat.SubjectPublicKeyInfo
            )           
        print(pem.decode())
        
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
        
        # Convert signature to base64 and decode it in order to print it (then print it).
        print(base64.b64encode(signature).decode())
        
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
            print(True)
        except:
            print(False)


# Define zero-hashes array that map between tree depth to hash of all zeros below.
# The array at the location i holds an hash of a tree at depth i where all of its leaves are zeros.
zero_hashes = []
zero_hashes.append(hash('0'))
for i in range(0, 255):
    zero_hashes.append(hash(zero_hashes[i] + zero_hashes[i]))
zero_hashes = zero_hashes[::-1]


# This function help SMT's node to get its value even if one of its child is None.
def set_inner_val(node, d):
    
    if node.left is None:
        left = zero_hashes[d]
    else:
        left = node.left.hash
        
    if node.right is None:
        right = zero_hashes[d]
    else:
        right = node.right.hash
        
    return left + right

# Define a Sparse Merkle Tree class:
class SparseMerkleTree:
    
    # Sparse Merkle Tree constructor.
    def __init__(self):
        self.rmt = MerkleTree()                 # Reuse MT code.
        self.rmt.root.hash = zero_hashes[0]     # Tree structure is fixed and all leaves are set to 0 by default.
    
    # Task 8 - mark a leaf.
    def mark_leaf(self, digest):
        
        # Turn the digest into a binary string.
        binary_hash = bin(int(digest.hexdigest(), 16))[2:].zfill(8)
        
        # Find the leaf location -- for each 1 in binary_hash, turn right, for each 0, turn left.
        me = self.rmt.root
        for bit in binary_hash:
            if bit == '1':
                if me.right is None:
                    me.right = Node(None)
                    me.right.parent = me
                me = me.right
            if bit == '0':
                if me.left is None:
                    me.left = Node(None)
                    me.left.parent = me
                me = me.left
                
        # Set leaf value and hash and update the smt object.
        me.value = binary_hash
        me.hash = hashlib.sha256('1'.encode('utf-8')).hexdigest()
        self.rmt.leaves.append(me)
        self.rmt.size += 1

        # Now we have to calculate the hashes of all the new nodes in the new path, from bottom to top.
        depth = 255
        while (me != self.rmt.root):
            me = me.parent
            depth -= 1
            me.value = set_inner_val(me, depth)
            me.hash = hash(me.value)
            
    # Task 9 - calculate root hash
    def calculate_root_hash(self):
        print(self.rmt.root.hash)
        
    # Task 10 - create a proof of inclusion
    def create_POI(self, digest):
        
        # Convert the given digest to a binary string.
        binary_hash = bin(int(digest.hexdigest(), 16))[2:].zfill(8)    
        
        # Look for the leaf in the marked-leaves array.
        me = None
        for leaf in self.rmt.leaves:
            if leaf.value == binary_hash:
                me = leaf
                break
        
        # If it isn't there, return, this digest is not in the tree.
        if me == None:
            print()
            return
        
        # Print A of the requested format.
        print(self.rmt.root.hash + ' ')
        
        # Print B of the requested format - from bottom to top.
        depth = 255
        while (me != self.rmt.root):
            if (me.brother() == None):
                print(zero_hashes[depth])
            else:
                print(me.brother().hash)
            me = me.parent
            depth -= 1
        






# DEBUG display -- prints the tree in in-order.
def display(node):
    if node.left is not None:
        display(node.left)
    print('value: ' + node.value[0:15] + ' hash: ' + node.hash[0:15])
    if node.right is not None:
        display(node.right)








# The 'main':
mt = MerkleTree()
smt = SparseMerkleTree()
while (1):
    
    args = input().split(' ', 1)
    
    try:
        operation = int(args[0])
    except:
        continue

    if (operation == 1):
        if (len(args) != 2):
            print()
            continue
        else:
            mt.add_leaf(args[1])
            
    if (operation == 2):
        mt.calculate_root_hash()
        
    if (operation == 3):
        if (len(args) != 2):
            print()
            continue
        else:
            print(mt.create_POI(args[1]))

    if (operation == 4):
        if (len(args) != 3):
            print()
            continue
        else:
            mt.check_POI(args[1], args[2])

    if (operation == 5):
        mt.create_keys()
        
    if (operation == 6):
        if (len(args) != 2):
            print()
            continue
        else:
            skey = args[1] + '\n'
            line = input()
            while (len(line) > 0):
                skey += line + '\n'
                line = input()
            skey = skey.replace('\n\n', '\n')
            mt.create_STH(skey)
        
    if (operation == 7):
        if (len(args) != 2):
            print()
            continue
        else:
            pkey = args[1] + '\n'
            line = input()
            while (len(line) > 0):
                pkey += line + '\n'
                line = input()
            pkey = pkey.replace('\n\n', '\n')
            
            additional_input = input()
            while (additional_input == ''):
                additional_input = input()
                
            additional_input = additional_input.split(' ')
            signature = additional_input[0]
            text = additional_input[1]
            
            mt.verify_signature(pkey, signature, text)
    
    if (operation == 8):
        DEBUG = hashobj = hashlib.sha256(args[1].encode())
        smt.mark_leaf(DEBUG)
        
    if (operation == 9):
        smt.calculate_root_hash()
        
    if (operation == 10):
        if (len(args) != 2):
            print()
            continue
        else:
            DEBUG = hashobj = hashlib.sha256(args[1].encode())
            smt.create_POI(DEBUG)
    
    
    
    
    
    # Debug display:
    if (operation == 0):
        display(mt.root)
    if (operation == 20):
        display(smt.rmt.root)
        




