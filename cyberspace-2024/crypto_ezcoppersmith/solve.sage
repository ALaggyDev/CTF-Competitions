from Crypto.Util.number import long_to_bytes

n = 18644771606497209714095542646224677588981048892455227811334258151262006531336794833359381822210403450387218291341636672728427659163488688386134401896278003165147721355406911673373424263190196921309228396204979060454870860816745503197616145647490864293442635906688253552867657780735555566444060335096583505652012496707636862307239874297179019995999007369981828074059533709513179171859521707075639202212109180625048226522596633441264313917276824985895380863669296036099693167611788521865367087640318827068580965890143181999375133385843774794990578010917043490614806222432751894223475655601237073207615381387441958773717
ct = 814602066169451977605898206043894866509050772237095352345693280423339237890197181768582210420699418615050495985283410604981870683596059562903004295804358339676736292824636301426917335460641348021235478618173522948941541432284037580201234570619769478956374067742134884689871240482950578532380612988605675957629342412670503628580284821612200740753343166428553552463950037371300722459849775674636165297063660872395712545246380895584677099483139705934844856029861773030472761407204967590283582345034506802227442338228782131928742229041926847011673393223237610854842559028007551817527116991453411203276872464110797091619


def fermatfactor(N):
    # This works because p and q are quite close together
    if N <= 0:
        return [N]
    if is_even(N):
        return [2, N/2]
    a = ceil(sqrt(N))
    while not is_square(a ^ 2-N):
        a = a + 1
    b = sqrt(a ^ 2-N)
    return [a - b, a + b]


[p, q] = fermatfactor(n)

d = pow(0x10001, -1, (p - 1) * (q - 1))
flag = pow(ct, d, n)

print(long_to_bytes(int(flag))[70:-70])