from hashlib import sha256
import os
from utils import listener

FLAG = b"crypto{???????????????????????????????????????}"
flen = len(FLAG)
assert flen == 47

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)

class Challenge:
    def __init__(self):
        self.before_input = "Welcome to the saplins implementation\n"
        self.secret = os.urandom(64-flen)
        self.datas = self.secret + FLAG
        self.nodes = []
        self.build_saplin()
        self.preview_used = False

    def build_saplin(self):
        self.nodes.append([hash256(self.datas[i:i+8]) for i in range(0,64,8)])
        self.nodes.append([merge_nodes(*self.nodes[0][i:i+2]) for i in range(0,8,2)])
        self.nodes.append([merge_nodes(*self.nodes[1][i:i+2]) for i in range(0,4,2)])
        self.nodes.append([merge_nodes(*self.nodes[2][0:2])])
        for i in range(3):
            following_node = self.nodes[i+1][0]
            self.nodes[i].append(following_node)

    def saplin_proof(self, user_input):
        return user_input == self.nodes[-1][0]

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "get_node":
            self.balance_validated = None
            try:
                wanted_node = int(your_input["node"])
                if not self.preview_used and wanted_node < len(self.nodes[0])-1: 
                    node = self.nodes[0][wanted_node].hex()
                    self.preview_used = True
                    return {"msg": node}
                else:
                    return {"error": "You can't preview this!"}
            except Exception as e:
                return {"error": str(e)}
            
        elif your_input["option"] == "do_proof":
            try:
                hsh =  bytes.fromhex(your_input["root"])
                if self.saplin_proof(hsh):
                    return {"msg":f"{FLAG}"}
                else:
                    return {"msg": "you failed!"}
            except Exception as e:
                return {"error": str(e)}
        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13432)
