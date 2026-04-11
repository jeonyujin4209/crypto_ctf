"""André Encoding — each FLAG byte b encodes as an isogeny of degree 2^64 * b.

Recover b via Weil pairing compatibility:
    e(phi(P), phi(Q)) = e(P, Q) ^ deg(phi) = e(P, Q) ^ (2^64 * b)

Each ciphertext lies on a DIFFERENT codomain curve; reconstruct its a,b
from the two image points, then compute the pairing there (it lives in
the same mu_N subgroup of F_p^2*).
"""
import json
proof.all(False)

p = 37 * 2^64 * lcm(range(1, 256)) - 1
F.<i> = GF(p^2, modulus=[1, 0, 1])
E = EllipticCurve(F, [0, 1])
E.set_order((p + 1)^2)

P = E(2754452008418475544762931777380298061286322242088097042789979017337032668335152047250270118628626846112409632316814344852346179989*i + 300888031019145372993855450123312195268855753102882163072967372426589237335996165853668912727448513477444811191182550244111536735,
      4048396253042221946332182039831591283289177370092736377609511682595711744157657185583897171948127827836521892887941707373829426385*i + 5574313210012278375687658199880462698154719575075630281638825753946911987283962578905520742770486366773314976292767579688991668535)
Q = E(1914292834750542008365772941838940247194316211832948370075234167086803005671626788818592170824160266813720050022811399854833864570*i + 675917976944321956275103708696442108160242821688340828072457829850507425923003867371226253254729899087222613984510532839645132037,
      1353413969699500553835259943514301405386193613479830974260135363453012387178560466458631824224103775101292443946360403995987929735*i + 2642848780435012471695812611372313188888541702956899224702856112971832879700145426992696527731460150858414996112482220450878252755)

with open("output.txt") as f:
    ct = json.load(f)

N = p + 1
alpha = P.weil_pairing(Q, N)
print(f"alpha computed")

# Table: alpha^(2^64 * b) → b for b in [1, 256)
print("Precomputing table...")
alpha_64 = alpha^(2^64)
table = {}
cur = alpha_64  # b=1
for b in range(1, 256):
    table[cur] = b
    cur *= alpha_64

def parse_F(l):
    return F(l[0]) + F(l[1]) * i

flag_bytes = []
for idx, item in enumerate(ct):
    x1 = parse_F(item["P"]["x"])
    y1 = parse_F(item["P"]["y"])
    x2 = parse_F(item["Q"]["x"])
    y2 = parse_F(item["Q"]["y"])
    a_coef = (y1^2 - y2^2 - x1^3 + x2^3) / (x1 - x2)
    b_coef = y1^2 - x1^3 - a_coef * x1
    E_new = EllipticCurve(F, [a_coef, b_coef])
    E_new.set_order((p + 1)^2)
    phi_P = E_new(x1, y1)
    phi_Q = E_new(x2, y2)
    beta = phi_P.weil_pairing(phi_Q, N)
    if beta in table:
        flag_bytes.append(table[beta])
    else:
        print(f"[{idx}] no match")
        flag_bytes.append(ord("?"))
    if idx % 5 == 0:
        print(f"  [{idx}] {bytes(flag_bytes).decode(errors='replace')}")

print()
print("FLAG:", bytes(flag_bytes).decode(errors='replace'))
