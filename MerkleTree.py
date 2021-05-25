import hashlib

# Defining a Node:
class Node:
    def __init__(self, value):
        self.parent = None
        self.value = value
        if (value is not None):
            self.hash = hashlib.sha256(value.encode('utf-8')).hexdigest()
        self.left = None
        self.right = None

# This function gets a number n and return True if and only if n is a power of 2.
def is_power_of_two(n):
    if (n == 0):
        return False
    while (n != 1):
        n = n / 2
        if (n % 2 != 0 and n != 1):
            return False
    return True


# This function get a tree (Node type) and return its rightest leaf.
def find_newest_leaf(tree):
    if (tree.right is not None):
        return find_newest_leaf(tree.right)
    elif (tree.left is not None):
        return find_newest_leaf(tree.left)
    else:
        return tree
      
  
# Defining the Merkle Tree object:
class MerkleTree:

    # Merkle Tree constructor.
    def __init__(self):
        self.root = Node(None)
        self.size = 0
        self.leaves = []
        

    # Task 1 - add leaf
    def add_leaf(self, value):
        
        if (self.size == 0):
            self.root = Node(value)
            self.leaves.append(self.root)
            
        elif (is_power_of_two(self.size)):
            print(str(self.size) + " is a power of 2")    # Debug
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
            
        else:
            print(str(self.size) + " is NOT a power of 2")    # Debug
            rightest = find_newest_leaf(self.root)
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
            
        self.size += 1
        print("Tree size: " + str(self.size))    # Debug
        

    # Task 2 - calculate signed tree hash
    def calculate_STH(self):
        if self.size != 0:
            print(self.root.hash)
        else:
            print('No nodes yet. Please add values using command 1.')
            
    # Task 3 - create a proof os inclusion
    def create_POI(self, x):
        x = int(x)               # Need to secure!
        me = self.leaves[x]      # Need to secure!
        print(self.root.hash + " ")
        while (me != self.root):
            if (me.parent.left == me):
                print(me.parent.right.hash + " ")
            else:
                print(me.parent.left.hash + " ")
            me = me.parent
            

# DEBUG display -- prints the tree in in-order.
def display(node):
    if node.left is not None:
        display(node.left)
    print('value: ' + node.value[0:15] + ' hash: ' + node.hash[0:15])
    if node.right is not None:
        display(node.right)


# The "main":
mk = MerkleTree()
while (1):
    command = input('Please enter a commnad number and input: ')
    args = command.split(' ')
    try:
        operation = int(args[0])
    except:
        print('Error: couldn\'nt parse request.')
        continue

    if (operation == 1):
        if (len(args) != 2):
            print("Error: missing or too many arguments.")
        else:
            mk.add_leaf(args[1])
            
    if (operation == 2):
        mk.calculate_STH()
        
    if (operation == 3):
        if (len(args) < 2):
            print("Error: not enough arguments.")
        else:
            mk.create_POI(args[1])
    
    
    # Debug display:
    if (operation == 0):
        display(mk.root)
