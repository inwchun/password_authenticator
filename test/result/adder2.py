import sys
import numpy as np

filename = sys.argv[1]

with open(filename) as f:
    key = [float(line.rstrip().split()[0]) for line in f]

with open(filename) as f:
    sign = [float(line.rstrip().split()[1]) / 1000 for line in f]

print("Average of key: " + str(sum(key)/len(key)))
print("Average of sign: " + str(sum(sign)/len(sign)))
print("std of key: " + str(np.std(key)))
print("std of sign: " + str(np.std(sign)))