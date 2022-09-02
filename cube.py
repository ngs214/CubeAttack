import itertools as it
from timeit import timeit
from typing import Dict, List, Optional, Set, Tuple, Union
import re
import numpy as np


from present import Present
# Cube攻击实现


class Cube:
    def __init__(self, encryption_algo, test_times=20, max_degree=2) -> None:
        self.max_degree = max_degree
        self._encryption_algo_checker(encryption_algo)
        # 检查传入的加密算法格式
        self.encryption_algo = encryption_algo
        self.test_times = test_times
        self.k_len, self.v_len = self.encryption_algo.get_len()
        self.hex_k_len = self.k_len >> 2
        self.hex_v_len = self.v_len >> 2
        # 十六进制下对应的密钥,明文长度

    # tool functions
    def _encryption_algo_checker(self, algo) -> None:
        try:
            k_len,v_len = algo.get_len()
        except:
            raise AttributeError("传入的加密算法无所需的类方法get_len()")
        test_key = "0" * (k_len >> 2)
        test_plaintext = "0" * (v_len >> 2)
        try:
            ciphertext = algo(test_key).cipher(test_plaintext)
        except Exception as e:
            print("加密算法内部运行错误")
            print(e)
        if ciphertext[-1] == " ":
            raise ValueError("输出格式错误，要求不以空格结尾")
        ciphertext = ciphertext.replace(" ", "").upper()
        ciphertext_form = re.compile(
            "(0x)?[0-9A-F]{{{}}}".format(v_len >> 2),
        )
        # 形如"(0x)0123456789ABCDEFabcd"
        # 注意此处{{{}}}外侧的两个大括号是一个大括号的转义形式，而内部的大括号对应format的输入，
        # 整体意思类似于“{self.v_len >> 2}”
        if not re.fullmatch(ciphertext_form, ciphertext):
            raise ValueError(
                "输出格式错误，要求{}位十六进制数字符串".format(v_len >> 2),
                ciphertext,
            )


    def _hex_num_to_bin_list(self, hex_num: str, bit_limit: int) -> List[str]:
        dec_num = int(hex_num, 16)
        bin_list = list(bin(dec_num)[2:])
        bin_list = [0 if s == "0" else 1 for s in bin_list]
        # bin(dec_num)为字符串，去除头部的0b
        bin_list = [0]*(bit_limit - len(bin_list)) + bin_list
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
        hex_num = hex(int(hex_1, 16) ^ int(hex_2, 16))[2:]
        hex_num = "0" * (len(hex_1) - len(hex_num)) + hex_num
        return hex_num.upper()

    def _get_prin_poly_sum_by_poly(self, poly, index_set: Set[int]) -> int:
        # 返回加密算法实例为poly，指标集为index_set时的主多项式和
        poly_sum = 0
        index_list = list(index_set)
        for i in range(2 ** len(index_list)):
            # 选取i对应的二进制表示，从而遍历指标集
            digit = 0
            plain_list = ["0"] * self.v_len
            while (digit < len(index_list)):
                if (i >> digit) & 1:
                    plain_list[index_list[digit]] = "1"
                digit += 1
            plaintext = self._bin_list_to_hex_num(plain_list)
            cipertext = poly.cipher(plaintext)
            check_bit = int(cipertext[-1], 16) & 1
            # 取最后一位bit作校验位
            poly_sum ^= check_bit
        return poly_sum

    def _get_prin_poly_sum_by_key(self, key: str, index_set: Set[int]) -> int:
        # 返回密钥为key的加密算法实例，指标集为index_set时的主多项式和
        poly = self.encryption_algo(key)
        return self._get_prin_poly_sum_by_poly(poly, index_set)

    def _BLR_linear_test(self, index_set: Set[int]) -> bool:
        n = 0
        all_p_sum = 0
        zero_key = "0" * self.hex_k_len
        p_zero = self._get_prin_poly_sum_by_key(zero_key, index_set)
        while (n < self.test_times):
            # 求得密钥为0时的主多项式和p(0)
            # 随机选取两个密钥，求得相应的主多项式和: p(k1)和p(k2)
            # 再将两个密钥异或，求得相应的主多项式和p(k1^k2)
            # 验证是否满足p(0) + p(k1) + p(k2) = p(k1^k2)
            # 不满足则此时指标集过小，返回False
            hex_chars = ["0", "1", "2", "3",
                         "4", "5", "6", "7",
                         "8", "9", "A", "B",
                         "C", "D", "E", "F",
                         ]
            test_key_1 = "".join(np.random.choice(hex_chars, self.hex_k_len))
            p_1 = self._get_prin_poly_sum_by_key(
                test_key_1,
                index_set,
            )
            test_key_2 = "".join(np.random.choice(hex_chars, self.hex_k_len))
            p_2 = self._get_prin_poly_sum_by_key(
                test_key_2, index_set)
            all_p_sum += p_1 + p_2
            test_key_1_and_2 = self._hex_xor(
                test_key_1,
                test_key_2,
            )
            p_1_and_2 = self._get_prin_poly_sum_by_key(
                test_key_1_and_2,
                index_set,
            )
            if p_zero ^ p_1 ^ p_2 != p_1_and_2:
                return False
            n += 1
        # all_p_sum 是所有p_1和p_2的和，若其等于0或2 * test_times，则主多项式和全为0或1
        # 此时指标集过大，返回False
        if all_p_sum == 0 or all_p_sum == 2 * self.test_times:
            return False
        return True

    def _get_index_sets(self) -> List[Set[int]]:
        index_sets = []
        for degree in range(1, self.max_degree + 1):
            all_index_combinations = it.combinations(range(self.v_len), degree)
            all_index_sets = map(set, all_index_combinations)
            feasible_index_sets = filter(self._BLR_linear_test, all_index_sets)
            index_sets.extend(feasible_index_sets)
        return index_sets

    def _get_super_poly(self, index_set: Set[int]) -> Tuple[int, int]:
        zero_key = "0" * self.hex_k_len
        p_zero = self._get_prin_poly_sum_by_key(zero_key, index_set)
        for k in range(self.k_len):
            # 遍历仅一位是1，其余位都是0时
            k_key = hex(1 << (self.k_len - k - 1))[2:]
            k_key = "0" * (self.hex_k_len - len(k_key)) + k_key
            # 补全前置0
            p_k = self._get_prin_poly_sum_by_key(k_key, index_set)
            if p_k ^ p_zero:
                return (k, p_zero)
        return None
        # 返回None时可能是test_times很小，导致选取了错误的指标集，无对应超级多项式,
        # 此时直接舍去此指标集

    # preprocess function
    def _preprocess(self) -> List[Tuple[set[int], Tuple[int, int]]]:
        index_sets = self._get_index_sets()
        index_set_and_super_poly_pair_list = []
        for index_set in index_sets:
            super_poly = self._get_super_poly(index_set)
            if super_poly:
                index_set_and_super_poly_pair_list.append(
                    (index_set, super_poly),
                )
        return index_set_and_super_poly_pair_list

    # attack function
    def attack(self, poly):
        index_set_and_super_poly_pair_list = self._preprocess()
        if index_set_and_super_poly_pair_list:
            result = {}
            for index_set, super_poly in index_set_and_super_poly_pair_list:
                if super_poly[0] in result:
                    # 重复的超级多项式
                    continue
                else:
                    prin_poly_sum = self._get_prin_poly_sum_by_poly(
                        poly,
                        index_set,
                    )
                    k, constant = super_poly
                    result[k] = prin_poly_sum ^ constant
                    # 模二运算
        return sorted(result.items(), key=lambda pair: pair[0])
