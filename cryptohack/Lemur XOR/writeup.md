# Lemur XOR
- **출처**: CryptoHack - Introduction
- **난이도**: 40 pts
- **카테고리**: XOR
- **technique**: image_xor, visual_xor

## 문제 요약
두 이미지가 같은 키로 XOR됨. 두 이미지를 서로 XOR하면 키가 상쇄되어 원본이 드러남.

## 풀이
1. PIL/numpy로 두 이미지의 RGB 픽셀 배열 로드
2. 픽셀 단위 XOR → 결과 이미지에 플래그 텍스트 출현

**원리**: A⊕K XOR B⊕K = A⊕B (키 K 상쇄)

## 플래그
`crypto{X0Rly_n0t!}`
