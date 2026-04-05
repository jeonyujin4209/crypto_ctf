#!/usr/bin/env python3

from PIL import Image
import numpy as np

lemur = np.array(Image.open("lemur.png"))
flag = np.array(Image.open("flag.png"))

result = lemur ^ flag
Image.fromarray(result.astype("uint8")).save("xor_result.png")
# 이미지에 플래그 텍스트가 보임
# crypto{X0Rly_n0t!}
