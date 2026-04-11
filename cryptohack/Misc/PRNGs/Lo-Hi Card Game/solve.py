"""
Lo-Hi Card Game (150pts) — LCG state recovery from base-52 card digits

The server's RNG is LCG mod p=2^61-1 with unknown A,B. Each rng.next()
output is rebased to base 52 and each digit becomes a deck-index card.
We read card indices directly from the server's response, reconstruct 3
consecutive RNG outputs n0,n1,n2, then solve for A,B via:
    A = (n2-n1)*(n1-n0)^-1 mod p   B = n1 - A*n0 mod p
and predict every future card.

Boundary detection: the server's "I will reshuffle the deck after N rounds"
message is emitted in a round iff THIS round's deal_card emptied the
current rebase sequence (setting game.num_deals). Round 1's message is
special (num_deals was initialized during Game.__init__). Subsequent
shuffle messages tell us L_i for each sequence i.

Layout:
    Round 1 reveals card 0 (MSD of seq 0) and reports L_0.
    Round k reveals card k-1 (0-indexed).
    Reshuffle msg at round k means cards[k-1] ... are getting close to the
    boundary — specifically, the deal_card call in round k dealt the LAST
    card of the CURRENT sequence. That card will be shown in round k+1's
    response as `hand`. L_{next} is revealed in this round's shuffle msg.

So: Round L_0 - 1 has shuffle msg with L_1.
    Round L_0 + L_1 - 1 has shuffle msg with L_2.
    ...
"""
import json
import re
import socket

HOST = "socket.cryptohack.org"
PORT = 13383
P = 2**61 - 1

VALUES = ['Ace', 'Two', 'Three', 'Four', 'Five', 'Six',
          'Seven', 'Eight', 'Nine', 'Ten', 'Jack', 'Queen', 'King']
SUITS = ['Clubs', 'Hearts', 'Diamonds', 'Spades']


def card_to_index(card_str):
    m = re.match(r"(\w+) of (\w+)", card_str)
    v, s = m.group(1), m.group(2)
    return SUITS.index(s) * 13 + VALUES.index(v)


def value_of(card_idx):
    return card_idx % 13


def recv_line(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b""
    while not buf.endswith(b"\n"):
        c = sock.recv(4096)
        if not c:
            break
        buf += c
    return buf.decode()


def send_json(sock, obj):
    sock.send((json.dumps(obj) + "\n").encode())


def horner(digits_msd_first, b=52):
    n = 0
    for d in digits_msd_first:
        n = n * b + d
    return n


def digits_of(n, b=52):
    if n < b:
        return [n]
    return [n % b] + digits_of(n // b, b)


def choose_blind_bet(hand_val):
    # Pure observation: minimize expected loss
    if hand_val < 6:
        return "h"
    elif hand_val > 6:
        return "l"
    else:
        return "h"  # tie-break


def choose_smart_bet(hand_val, hidden_val):
    # Equal values always lose -2 regardless
    if hidden_val == hand_val:
        return "l"  # doesn't matter
    return "l" if hidden_val < hand_val else "h"


def main():
    sock = socket.create_connection((HOST, PORT))

    # Round 1 response comes first
    r = json.loads(recv_line(sock))
    cards = [card_to_index(r["hand"])]  # card 0
    seq_lens = []
    m = re.search(r"reshuffle the deck after (\d+) rounds", r["msg"])
    assert m, f"no initial shuffle msg: {r}"
    seq_lens.append(int(m.group(1)))  # L_0
    print(f"[*] L_0 = {seq_lens[0]}  card 0 = {VALUES[cards[0]%13]} of {SUITS[cards[0]//13]}")
    dollars = r["$"]

    # Observe until we have 3 full sequences and enough cards
    while len(seq_lens) < 3 or len(cards) < sum(seq_lens[:3]):
        last_card_val = value_of(cards[-1])
        bet = choose_blind_bet(last_card_val)
        send_json(sock, {"choice": bet})
        r = json.loads(recv_line(sock))
        if "error" in r:
            print(f"[!] error: {r}")
            return
        cards.append(card_to_index(r["hand"]))
        dollars = r["$"]
        m = re.search(r"reshuffle the deck after (\d+) rounds", r["msg"])
        if m:
            new_len = int(m.group(1))
            seq_lens.append(new_len)
            print(f"  [r{r['round']}] ${dollars}  new seq len = {new_len}  (seq_lens={seq_lens})")
        if r["round"] % 5 == 0:
            print(f"  [r{r['round']}] ${dollars} cards={len(cards)} seq_lens={seq_lens}")

    print(f"[*] obs done: ${dollars}  cards={len(cards)}  seq_lens={seq_lens}")

    # Split cards into sequences
    L0, L1, L2 = seq_lens[:3]
    seq0 = cards[0:L0]
    seq1 = cards[L0:L0+L1]
    seq2 = cards[L0+L1:L0+L1+L2]
    n0 = horner(seq0)
    n1 = horner(seq1)
    n2 = horner(seq2)
    print(f"[*] n0={n0}\n    n1={n1}\n    n2={n2}")

    # Solve LCG (A, B)
    diff1 = (n1 - n0) % P
    diff2 = (n2 - n1) % P
    inv_d1 = pow(diff1, -1, P)
    A = (diff2 * inv_d1) % P
    B = (n1 - A * n0) % P
    print(f"[*] A = {A}\n    B = {B}")
    assert (A * n0 + B) % P == n1
    assert (A * n1 + B) % P == n2
    print("[+] LCG verified")

    # Predict future RNG states and flatten to card queue. We've already
    # observed L0+L1+L2 cards (cards 0..sum-1). Next card to be revealed
    # is cards[sum]  = card number (L0+L1+L2) = MSD of seq 3 (state n_3).
    total_consumed = L0 + L1 + L2
    future_cards = []
    state = n2
    for _ in range(30):  # generate plenty
        state = (A * state + B) % P
        future_cards.extend(digits_of(state)[::-1])  # MSD-first

    # Known cards: `cards` (observed). Extended cards: cards + future_cards.
    all_cards = list(cards) + future_cards
    print(f"[*] predicted {len(future_cards)} future cards; queue size {len(all_cards)}")

    # Continue betting rounds with full knowledge.
    # At round k, hand = cards[k-1], hidden = cards[k]. We bet on comparison.
    round_num = L0 + L1 + L2  # last round observed
    target_round = 200
    while round_num < target_round - 1:
        # About to send bet for round round_num + 1
        hand_idx = all_cards[round_num - 1]  # 1-indexed: round k has cards[k-1] as hand
        hidden_idx = all_cards[round_num]    # next card to be revealed
        bet = choose_smart_bet(value_of(hand_idx), value_of(hidden_idx))
        send_json(sock, {"choice": bet})
        r = json.loads(recv_line(sock))
        if "error" in r:
            print(f"[!] error at r{round_num+1}: {r}")
            return
        round_num = r["round"]
        dollars = r["$"]
        observed_hand = card_to_index(r["hand"])
        if observed_hand != hidden_idx:
            print(f"[!] MISMATCH at r{round_num}: expected {hidden_idx}, got {observed_hand}")
            return
        if round_num % 25 == 0:
            print(f"  [r{round_num}] ${dollars}  bet={bet}")

    # After round 200 is completed, one more request triggers the flag msg
    send_json(sock, {"choice": "l"})
    r = json.loads(recv_line(sock))
    print(f"[+] r200: {r}")
    send_json(sock, {"choice": "l"})
    r2 = json.loads(recv_line(sock))
    print(f"[+] final: {r2}")
    sock.close()


if __name__ == "__main__":
    main()
