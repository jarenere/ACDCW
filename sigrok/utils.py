
def chech_xor(l):
    xor = 0
    for i in range(int((len(l)-2)/2)):
        xor = xor ^ int(l[2*i:2*i+2], 16)

    return xor == int(l[-2:], 16)
