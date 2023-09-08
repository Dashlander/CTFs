from binascii import unhexlify

n = 227010481295437363334259960947493668895875336466084780038173258247009162675779735389791151574049166747880487470296548479
e = 65537
c = 103041042558067679617617907514217238456749845848888410352361736997390105286660564458561436949519697513397681148539956095
factors = [327414555693498015751146303749141488063642403240171463406883, 693342667110830181197325401899700641361965863127336680673013]

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b%a, a)
        return (g, x - (b//a)*y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if(g != 1):
        return -1
    return x%m

def solve_rsa(factors, c):

    ds = []
    for i in range(len(factors)):
        ds.append(modinv(e, factors[i] - 1))

    m = factors[0]
    ts = []
    for i in range(1, len(factors)):
        ts.append(modinv(m, factors[i]))
        m = m*factors[i]
    xs = []
    for i in range(len(factors)):
        xs.append(pow((c%factors[i]), ds[i], factors[i]))

    x = xs[0]
    m = factors[0]

    for i in range(1, len(factors)):
        x += m*((xs[i] - x % factors[i]) * (ts[i - 1] % factors[i]))
        m = m*factors[i]

    print("[*] flag: {}".format(unhexlify(hex(x%m)[2:])))

solve_rsa(factors, c)
