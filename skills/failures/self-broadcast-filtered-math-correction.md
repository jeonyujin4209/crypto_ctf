# Self-Broadcast Filter: MPC Math 누락 함정

type: failure
tags: [mpc, broadcast, self-dm, reconstruction, vss, secret-sharing]

## 실수 패턴

분산 프로토콜(MPC, secret sharing, broadcast)에서 우리가 다른 멤버들에게 DM/broadcast로 share를 보낼 때, **서버가 self-DM을 echo하지 않으면** 우리는 자신의 contribution을 못 받음.

수식 reconstruction 시 "받은 share 합 = 전체 합" 이라고 가정하면 우리 contribution이 빠진 부분 결과가 나옴 → 결과가 secret과 다름.

## 사례 1: Pedersen PSS recommittee (The Black Talon)

Bot이 NGS(N) DM을 모든 new_users에게 보냄. 코드:
```rust
if myself == to {
    self.enqueue_self(myself, "@", message);  // local
} else {
    self.send_raw_message_to(&format!("@{to}"), &message.to_string()).await
}
```

→ peer 자기 자신에게는 local enqueue (실제 broadcast 안 일어남). 다른 client는 못 받음.

Server side:
```rust
if (dm_target || in_channel)
    && Some(&from) != ns.users[user_id].as_ref().map(|u| &u.name)  // skip sender
{
    writer.send_command(...).await...
}
```

→ broadcaster 본인은 echo 안 받음.

**공격자 영향**: 우리가 K 개 us-positions에서 NGS(N)를 us-as-new-user 에게 보내면 **하나도 못 받음** (K 개 self-DMs 모두 필터). 

reconstruction:
```python
# 받은 NGS(N) values만 sum:
n_per_key[k] = sum(received_NGS_N_values_at_key_k)
# 누락: K × (q - my_r_recomm) (우리 자신의 K us-positions 기여)
fp_k = (n_per_key[k] + pr_t) % q
# 결과: fp_k = secret + B_others(k) - K*(q-my_r)
#       = (정답) - 누락
```

**검증**: Lagrange interpolation → secret + constant offset. bytes 변환 시 garbage.

## 해결

K us-positions 에서 보낸 (받지 못한) self-DM 값을 **수동으로** n_per_key에 추가:
```python
self_n_contribution = (K_us_old * ((q - my_r_recomm) % q)) % q
for k in n_per_key:
    n_per_key[k] = (n_per_key[k] + self_n_contribution) % q
```

이후 Lagrange → secret matches.

## 사례 2: Multi-party shuffle/protocol broadcast

일반화: 각 party가 N party들에게 `share_i` 보내고 본인 share는 local 저장.
Reconstructor는 (a) 모든 received share + (b) own share를 합쳐야.

함정: 본인은 "내 share는 send했으니 fine"이라고 생각하지만 **received list에 없음**.

## 범용 교훈

분산 protocol attack 시:
1. **send_dm_to(self) handling 확인**: `if myself == to { enqueue_self / skip }` 패턴 찾기.
2. **server forwarding rule 확인**: `from != sender` 필터 보면 자기 메시지 못 받음.
3. **수학 verification**: 받은 share 합 ≠ 전체 합. 본인 contribution 따로 track.
4. **Sanity check**: Lagrange가 정답 가까운 가짜 값 주면 missing term 의심. 일정 offset이면 발견 쉬움.

## 디버그 시그널

- 받은 NGS/share count = N - K (where K = our positions). N (전체)에 못 미침.
- Recovered secret이 alphanumeric ASCII 범위 밖.
- 같은 polynomial의 다른 K_old values에서 다른 (잘못된) secret 나옴.

## 참고
- 솔버: `bbbctf/the-black-talon/solve/live_v5.py` (495-499 line)
- 관련 skill: `attack/pedersen-pss-k-position-accumulation`
