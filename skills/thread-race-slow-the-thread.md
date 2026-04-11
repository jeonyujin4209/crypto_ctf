---
name: thread-race-slow-the-thread
description: TOCTOU races where a background thread validates AFTER the main thread uses data — win by actively slowing the thread with a huge input
type: feedback
---

Several CryptoHack challenges spawn a `threading.Thread` to do a check and **don't `.join()` it** before returning the response. Example (Mister Saplin's Preview):

```python
def challenge(self, your_input):
    if your_input["option"] == "get_nodes":
        self.balance_validated = None
        ...
        self.balance_check(wanted_nodes)   # starts thread, returns immediately
        if self.balance_validated != False:
            return {"msg": ...}            # serialize and return
```

`balance_check` kicks off a `Thread(target=request_checker, ...)` and returns. The main thread then reads `self.balance_validated` — if the worker hasn't flipped it to `False` yet, the check passes and the nodes are returned.

**First instinct is wrong:** "it's a tight race, I'll spam connections and eventually win." You won't, because network round-trip (~50 ms) is 10⁴× longer than the worker loop. Every attempt, the worker finishes well before the main thread reads the flag.

**How to apply:** Look at what the worker thread does. If it's `sum(prices) over wanted_nodes` or any sum/product over `wanted_nodes[layer]`, send a huge count to stretch the inner loop:

```python
send_json(sock, {"option": "get_nodes", "nodes": f"1,{100_000_000}"})
```

Now the worker spends ~1–2 seconds on the arithmetic loop, while the main thread does `self.nodes[layer][:count]` (fast, the slice caps at the real list length → returns 4 hashes), serializes the response, and flushes it to the socket before the worker even finishes. You get the nodes without the credits being deducted.

**Key observation:** the main thread's work on the request is bounded (a few hashes), but the worker's work is `O(count)` where `count` is client-controlled. Asymmetry in how they scale with your input is the lever — exploit it.

Other pattern to look for: any validator running on a thread while the main path builds and returns data from the same resource. "Why is there a thread at all?" is usually the answer to "where's the race?"
