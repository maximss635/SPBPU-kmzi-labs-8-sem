from elliptic_cryptography import *


class SignParams:
    p = 57896044628890729911196718984933305846544100325488685311213142875135838763683
    q = 28948022314445364955598359492466652923270809441897180344196391207096541510137
    curve = EllipticCurve(1, 51597193811365919768190236681066502033803499635094541650610225403695076439048, p)
    P = EllipticCurvePoint(21371456824977467041033238171905463424508399897529674896678501178686263573482,
                           52962982709744467108853563358242537068648343861092009194618855518747612108192, curve)
