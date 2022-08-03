import sys
import numpy as np

filename = sys.argv[1]

with open(filename) as f:
    data = [float(line.rstrip()) for line in f]

print("Average: " + str(sum(data)/len(data)))
print("std: " + str(np.std(data)))