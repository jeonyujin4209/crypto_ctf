#!/usr/bin/env python3

"""
Vote for Pedro
If you want my flag, you better vote for Pedro! Can you sign your vote to the server as Alice?

Connect at socket.cryptohack.org 13375

Challenge files:
  - 13375.py
  - alice.key
"""

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener

FLAG = "crypto{????????????????????}"


class Challenge():
    def __init__(self):
        self.before_input = "Place your vote. Pedro offers a reward to anyone who votes for him!\n"

    def challenge(self, your_input):
        if 'option' not in your_input:
            return {"error": "You must send an option to this server"}

        elif your_input['option'] == 'vote':
            vote = int(your_input['vote'], 16)
            verified_vote = long_to_bytes(pow(vote, ALICE_E, ALICE_N))

            # remove padding
            vote = verified_vote.split(b'\00')[-1]

            if vote == b'VOTE FOR PEDRO':
                return {"flag": FLAG}
            else:
                return {"error": "You should have voted for Pedro"}

        else:
            return {"error": "Invalid option"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13375)
