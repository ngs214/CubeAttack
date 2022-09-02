import numpy as np
a = np.array([1,2,3],dtype=np.uint8)
b = np.array2string(a)
print("".join(b))