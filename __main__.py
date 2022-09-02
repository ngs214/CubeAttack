from time import time
from cube import Cube
from present import Present

# 导入加密算法
# 要求加密算法输入密钥，明文支持含空格不分大小写的十六进制字符串
# 输出密文格式为不含空格的不分大小写的十六进制字符串
# 要求加密算法类实现以下类方法
# @classmethod
# def get_len(cls) -> Tuple[int, int]:
#     return cls.key_len, cls.plaintext_len
# 返回该加密算法对应的密钥长度和明文长度
if __name__ == "__main__":
    start = time()
    encryption_algo = Present
    key = "01a48894154284298b7c"
    # 在此设置加密算法和密钥

    encryption_algo_instance = encryption_algo(key)
    # 创建加密算法实例

    my_cube = Cube(encryption_algo=encryption_algo,
                   test_times=20,
                   max_degree=2,
                   )
    # encryption_algo表示攻击的加密算法
    # test_times表示进行BLR线性测试时的阈值，当该值为N时，得到的随机一位密钥bit的置信度为1 - 2**(-N)
    # max_degree表示立方攻击选取的最高维度，该值越大，一次攻击获得的密钥bit越多。
    # 当攻击的加密算法较复杂时，需选取更大的值才能成功得到密钥bit。
    # 但是攻击运行时间随max_degree增大成指数增长，建议选取恰当的值。

    result = my_cube.attack(encryption_algo_instance)
    # 进行攻击
    with open("result.txt", "w") as f:
        f.write("index : value  \n")
        for index, value in result:
            f.write("{} : {} \n".format(index, value))
        # 按index输出攻击得到的密钥bit
        end = time()
        f.write("UseTime: {} seconds \n".format(round(end - start, 3)))
        # 输出攻击用时

        # 输出密钥二进制形式，进行对比
        f.write("Key : {}\n".format(key))
        key = key.replace(" ", "").upper()
        key = bin(int(key, 16))[2:]
        # key为字符串，去除头部的0b
        k_len = encryption_algo.get_len()[0]
        key = "0"*(k_len - len(key)) + key
        # 补足前置0
        for index, value in enumerate(key):
            f.write("{} : {} \n".format(index, value))
        for i in range(len(result)):
            if int(key[result[i][0]]) != result[i][1]:
                f.write("攻击获取的第{}位bit错误,\
                请尝试适当调大test_times\n".format(result[i][0]))
