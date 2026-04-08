from hashlib import sha256
from threading import Thread
import os
from utils import listener

FLAG = b"crypto{??????????????????????????????????????????????????????????????????}"

def hash256(data):
    return sha256(data).digest()

def merge_nodes(a, b):
    return hash256(a+b)

class Challenge:
    def __init__(self):
        self.before_input = "Welcome to the saplins previews system implementation!\n"
        self.datas = os.urandom(64)
        self.balance = 99
        self.nodes = []
        self.build_saplin()
        self.balance_validated = False
        self.layer_price = {0:20, 1:50, 2:110}

    def build_saplin(self):
        self.nodes.append([hash256(self.datas[i:i+8]) for i in range(0,64,8)])
        self.nodes.append([merge_nodes(*self.nodes[0][i:i+2]) for i in range(0,8,2)])
        self.nodes.append([merge_nodes(*self.nodes[1][i:i+2]) for i in range(0,4,2)])
        self.nodes.append([merge_nodes(*self.nodes[2][0:2])])

    def request_checker(self, wanted_nodes):
        # just checking if the balance has enough credits
        credits_needed = 0
        for layer in wanted_nodes.keys():
            for _ in range(wanted_nodes[layer]):
                credits_needed += self.layer_price[layer]

        if credits_needed > self.balance:
            self.balance_validated = False
        else:
            self.balance_validated = True
            self.balance -= credits_needed

    def balance_check(self, wanted_nodes):
        layers = wanted_nodes.keys()
        # dealing with trivials cases
        for layer in layers:
            if layer >= 3 or layer < 0:
                self.balance_validated = False
                return
        if 2 in layers and wanted_nodes[2] >= 1:
            # too high node even with the starting balance
            self.balance_validated = False
            return
        # dealing with common cases
        t = Thread(target=self.request_checker, args=[wanted_nodes])
        t.start()

    def saplin_proof(self, user_input):
        return user_input == self.nodes[-1][0]

    def challenge(self, your_input):
        if not "option" in your_input:
            return {"error": "You must send an option to this server"}

        if your_input["option"] == "get_nodes":
            self.balance_validated = None
            try:
                raw_wanted_nodes = your_input["nodes"].split(";")
                wanted_nodes = {int(layer.split(",")[0]): int(layer.split(",")[1]) for layer in raw_wanted_nodes}
                self.balance_check(wanted_nodes)
                if self.balance_validated != False:
                    nodes = []
                    for layer in wanted_nodes:
                        nodes.append(list(map(bytes.hex, self.nodes[layer][:wanted_nodes[layer]])))
                    return {"msg": str(nodes)}
                else:
                    return {"error": "You don't have enough credits!"}
            except Exception as e:
                return {"error": str(e)}

        elif your_input["option"] == "do_proof":
            try:
                hsh =  bytes.fromhex(your_input["root"])
                if self.saplin_proof(hsh):
                    return {"msg": FLAG.decode()}
                else:
                    return {"msg": "you failed!"}
            except Exception as e:
                return {"error": str(e)}
        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13414)

