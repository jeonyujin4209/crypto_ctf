"""Test killing 1 bot in isolation using local_kill_test.py pattern."""
import sys, os
sys.path.insert(0, r"D:/crypto_ctf/bbbctf/the-black-talon-the-black-talon/solve")
src = open("local_kill_test.py", encoding="utf-8").read()
src = src.replace("victims = [u for u in cm['users'] if u != PROT][:5]",
                  "victims = [u for u in cm['users'] if u != PROT][:1]")
exec(src)
