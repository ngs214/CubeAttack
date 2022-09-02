import re
from typing import Dict, List, Optional, Set, Tuple, Union

import numpy as np

# Present算法具体实现


class Present:
    key_len = 80
    plaintext_len = 64

    def __init__(self, key: str, default_round=4) -> None:
        key = key.replace(" ", "").upper()
        key_form = re.compile(r"(0x)?[0-9A-F]{20}")
        # 形如"(0x)0123456789ABCDEFabcd"
        if not re.fullmatch(key_form, key):
            raise ValueError("不是合法的密钥(20位十六进制数)", key)
        self._init_key = key
        self.default_round = default_round

    @classmethod
    def get_len(cls) -> Tuple[int, int]:
        # 返回key和plaintext长度
        return cls.key_len, cls.plaintext_len

    def _hex_num_to_bin_array(self, hex_num: str, bit_limit: int) -> List[str]:
        dec_num = int(hex_num, 16)
        bin_list = list(bin(dec_num)[2:])
        # bin(dec_num)为字符串，去除头部的0b
        bin_list = ["0"]*(bit_limit - len(bin_list)) + bin_list
        # 补足前置0
        return bin_list

    def _bin_list_to_hex_num(self, bin_list: List[str]) -> str:
        bin_num = "".join(bin_list)
        dec_num = int(bin_num, 2)
        hex_num = hex(dec_num)[2:]
        hex_num = "0" * ((len(bin_list) >> 2) - len(hex_num)) + hex_num
        # 补足前置0，即四位二进制0转为一位十六进制0
        return hex_num.upper()

    def _hex_xor(self, hex_1: str, hex_2: str) -> str:
        # 转换为十进制后异或，再转成十六进制，删去0x
        # 注意hex_1和hex_2应该同长度
        hex_num = hex(int(hex_1, 16) ^ int(hex_2, 16))[2:]
        hex_num = "0" * (len(hex_1) - len(hex_num)) + hex_num
        return hex_num.upper()

    def _S_box_substitution(self, text: str) -> str:
        S_box = {
            "0": "C",
            "1": "5",
            "2": "6",
            "3": "B",
            "4": "9",
            "5": "0",
            "6": "A",
            "7": "D",
            "8": "3",
            "9": "E",
            "A": "F",
            "B": "8",
            "C": "4",
            "D": "7",
            "E": "1",
            "F": "2",
        }
        new_text = "".join(map(lambda s: S_box[s], text))
        return new_text

    def _P_box_permutation(self, text: str) -> str:
        bin_list = self._hex_num_to_bin_array(
            text,
            bit_limit=self.plaintext_len,
        )
        new_bin_list = [0] * self.plaintext_len
        for i in range(63):
            new_bin_list[i * 16 % 63] = bin_list[i]
        new_bin_list[63] = bin_list[63]
        return self._bin_list_to_hex_num(new_bin_list)

    def cipher(self, plaintext: str) -> str:
        plaintext = plaintext.replace(" ", "")
        plaintext_form = re.compile(r"(0x)?[0-9A-F]{16}")
        if not re.fullmatch(plaintext_form, plaintext):
            raise ValueError("不是合法的明文(16位十六进制数)", plaintext)
        round_counter = 1
        key = self._init_key
        while (round_counter < self.default_round):
            # 轮密钥加，取key的低十六位与明文异或
            plaintext = self._hex_xor(key[0:16], plaintext)

            # S盒代换
            plaintext = self._S_box_substitution(plaintext)

            # P盒置换
            plaintext = self._P_box_permutation(plaintext)

            # 循环左移61位
            key_list = self._hex_num_to_bin_array(key, bit_limit=80)
            key_list = key_list[61:] + key_list[:61]

            # 为了减少二进制列表和十六进制字符串间的转换，将S盒置换头部置于后面

            # 取中间5位与轮数异或
            mid_bits = key_list[60:65]
            new_mid_bits = []
            for i in range(5):
                round_counter_bit = (round_counter >> (4 - i)) & 1
                mid_bit = int(mid_bits[i])
                new_mid_bits.append(str(round_counter_bit ^ mid_bit))
            key_list = key_list[0:60] + new_mid_bits + key_list[65:]

            # S盒置换头部
            key = self._bin_list_to_hex_num(key_list)
            head = key[0]
            new_head = self._S_box_substitution(head)[-1]
            # 取_S_box_substitution返回的最后一位。
            key = new_head + key[1:]
            round_counter += 1
        # 最后一轮白化
        cipher = self._hex_xor(key[0:16], plaintext)
        return cipher
