import hashlib
import sys

# Defining a Node:
class Node:
    def __init__(self, value):
        self.left = None
        self.right = None
        self.value = value
        self.hashed_value = hashlib.sha256(value.encode('utf-8')).hexdigest()

# Defining the Merkle Tree object:
class MerkleTree:

    def __init__(self):
        self.root = None
        self.nodes = []
        self.values = []

    def addLeaf(self, value):
        self.values.append(value)
        self.nodes = []
        for i in self.values:
            self.nodes.append(Node(i))
        while len(self.nodes) > 1:
            nodes = []
            for i in range(0, len(self.nodes), 2):
                left_child = self.nodes[i]
                if i + 1 < len(self.nodes):
                    right_child = self.nodes[i + 1]
                else:
                    nodes.append(self.nodes[i])
                    break
                    break
                parent = Node(left_child.hashed_value + right_child.hashed_value)
                parent.left = left_child
                parent.right = right_child
                nodes.append(parent)
            self.nodes = nodes
        self.root = self.nodes[0]

    def calculateSignedTreeHash(self):
        if self.root is not None:
            print(self.root.hashed_value)
        else:
            print('No nodes yet. Please add values using command 1.')

    # def createProofOfInclusion(self, leaf_number):


# DEBUG display -- prints the tree in in-order.
def display(node):
    if node.left is not None:
        display(node.left)
    print('value: ' + node.value[0:15] + ' hash: ' + node.hashed_value[0:15])
    if node.right is not None:
        display(node.right)

# The "main":
mk = MerkleTree()
while (1):
    command = input('Please enter a commnad number and input: ')
    arguments = command.split(' ')
    try:
        operation = int(arguments[0])
    except:
        print('Error: couldn\'nt parse request.')
        continue

    if (operation == 1):
        mk.addLeaf(arguments[1])
    if (operation == 2):
        mk.calculateSignedTreeHash()

        
    if (operation == 0):
        display(mk.root)
