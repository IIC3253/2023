import importlib
import random
import re
import sys
import os
from dataclasses import dataclass, field
from typing import Dict
import pytest
from config import RESULTS_PATH

ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


PATH = sys.argv[-1]
ALUMNO = sys.argv[-3]

assert os.path.isfile(PATH), f"No existe el archivo '{PATH}'"

PATH = PATH.replace(".ipynb", "")
print("PATH:", PATH)


@dataclass
class Testcase:
    msg: str
    inputs: list = field(default_factory=list)
    correct: bool = False

    def set_correct(self):
        self.correct = True
        self.msg = "Correcto!"


RESULTS: Dict[str, Testcase] = {
    # ElGamal, Zp*, Schnorr
    "test_order_identity_zpstar": Testcase("No se pudo ejecutar"),
    "test_distinct_encrypt_zpstar": Testcase("No se pudo ejecutar"),
    "test_encrypt_decrypt_zpstar": Testcase("No se pudo ejecutar"),
    "test_signatures_zpstar": Testcase("No se pudo ejecutar"),
    "test_fixed_signatures_zpstar": Testcase("No se pudo ejecutar"),
    # Elliptic Curve
    "test_order_identity_elliptic": Testcase("No se pudo ejecutar"),
    "test_order_not_prime_elliptic": Testcase("No se pudo ejecutar"),
    "test_incorrect_point_elliptic": Testcase("No se pudo ejecutar"),
    "test_distinct_encrypt_elliptic": Testcase("No se pudo ejecutar"),
    "test_encrypt_decrypt_elliptic": Testcase("No se pudo ejecutar"),
    "test_signatures_elliptic": Testcase("No se pudo ejecutar"),
    "test_fixed_signatures_elliptic": Testcase("No se pudo ejecutar"),
}


def pytest_sessionfinish(request: pytest.FixtureRequest):
    """whole test run finishes."""

    for key, result in RESULTS.items():
        if len(result.inputs) and not result.correct:
            result.msg = "Incorrecto:"

    with open(os.path.join(RESULTS_PATH, f"{ALUMNO}.txt"), "w", encoding="utf-8") as f:
        f.write(f"{ALUMNO}\n")
        f.write(f"Puntaje: {sum([1 for r in RESULTS.values() if r.correct])} / {len(RESULTS)} \n\n")
        f.write("-" * 40 + "\n\n")
        for key, result in RESULTS.items():
            f.write(f"{key}\n")
            f.write(f"{result.msg}\n\n")
            f.write("Info:\n")
            for i in result.inputs:
                f.write(f"{i}\n")
            f.write("\n")
            f.write("-" * 40 + "\n\n")


@pytest.fixture(scope="session", autouse=True)
def cleanup_after_tests(request):
    yield
    # Code to execute after all tests are done
    pytest_sessionfinish(request)


def cipher_to_str(cipher):
    return f"({cipher[0]}, {cipher[1]})"


class TestQ1:
    p = 5809605995369958062791915965639201402176612226902900533702900882779736177890990861472094774477339581147373410185646378328043729800750470098210924487866935059164371588168047540943981644516632755067501626434556398193186628990071248660819361205119793693985433297036118232914410171876807536457391277857011849897410207519105333355801121109356897459426271845471397952675959440793493071628394122780510124618488232602464649876850458861245784240929258426287699705312584509625419513463605155428017165714465363094021609290561084025893662561222573202082865797821865270991145082200656978177192827024538990239969175546190770645685893438011714430426409338676314743571154537142031573004276428701433036381801705308659830751190352946025482059931306571004727362479688415574702596946457770284148435989129632853918392117997472632693078113129886487399347796982772784615865232621289656944284216824611318709764535152507354116344703769998514148343807
    generator_value = 2
    order = 2904802997684979031395957982819600701088306113451450266851450441389868088945495430736047387238669790573686705092823189164021864900375235049105462243933467529582185794084023770471990822258316377533750813217278199096593314495035624330409680602559896846992716648518059116457205085938403768228695638928505924948705103759552666677900560554678448729713135922735698976337979720396746535814197061390255062309244116301232324938425229430622892120464629213143849852656292254812709756731802577714008582857232681547010804645280542012946831280611286601041432898910932635495572541100328489088596413512269495119984587773095385322842946719005857215213204669338157371785577268571015786502138214350716518190900852654329915375595176473012741029965653285502363681239844207787351298473228885142074217994564816426959196058998736316346539056564943243699673898491386392307932616310644828472142108412305659354882267576253677058172351884999257074171903

    notebook = importlib.import_module("ipynb.fs.full." + PATH)
    INIT_RAISED_ERROR = False

    try:
        group = notebook.ZpStar(p)
        generator = group.get_element(generator_value)
        receiver = notebook.SecretKeyHolder(group, generator, order)
        sender = notebook.PublicKeyHolder(receiver.get_public_key())
    except Exception as e:
        print(e)
        print("Error al cargar la clase ZpStar / Holders.")
        INIT_RAISED_ERROR = True

    def _generate_message():
        message = random.randint(0, TestQ1.p - 1)
        return TestQ1.group.get_element(message)

    def test_order_identity(self):
        case = RESULTS["test_order_identity_zpstar"]
        case.inputs = [
            "Generator**Order == Identity",
            f"Generator:    {TestQ1.generator}",
            f"Order:        {TestQ1.order}",
            f"Identity:     {TestQ1.group.get_identity()}",
        ]
        assert (
            TestQ1.generator**TestQ1.order == TestQ1.group.get_identity()
        ), "ZpStar: el test order_identity falla. El orden del grupo no es correcto."

        case.set_correct()

    def test_distinct_encrypt(self):
        case = RESULTS["test_distinct_encrypt_zpstar"]

        plaintext = TestQ1._generate_message()
        ciphertext_1 = TestQ1.sender.encrypt(plaintext)
        ciphertext_2 = TestQ1.sender.encrypt(plaintext)

        case.inputs = [
            "Encrypt(Plaintext) == Encrypt(Plaintext)",
            f"Plaintext:   {plaintext}",
            f"Ciphertext 1: {cipher_to_str(ciphertext_1)}",
            f"Ciphertext 2: {cipher_to_str(ciphertext_2)}",
        ]
        assert not ciphertext_1 == ciphertext_2, "ZpStar: El test distinct_encrypt falla."

        case.set_correct()

    def test_encrypt_decrypt(self):
        case = RESULTS["test_encrypt_decrypt_zpstar"]
        plaintext = TestQ1._generate_message()
        ciphertext = TestQ1.sender.encrypt(plaintext)

        case.inputs = [
            "Plaintext == Decrypt(Encrypt(Plaintext))",
            f"Plaintext:   {plaintext}",
            f"Ciphertext: {cipher_to_str(ciphertext)}",
        ]

        assert plaintext == TestQ1.receiver.decrypt(
            ciphertext
        ), "ZpStar: El test encrypt_decrypt falla."

        case.set_correct()

    def test_signatures(self):
        case = RESULTS["test_signatures_zpstar"]
        message_1 = TestQ1._generate_message()
        message_2 = TestQ1._generate_message()
        signature_1 = TestQ1.receiver.schnorr_signature(message_1)
        signature_2 = TestQ1.receiver.schnorr_signature(message_2)

        case.inputs = [
            "m1 con s1, m2 con s2, m2 NO con s1, m1 NO con s2",
            f"Message 1:   {message_1}",
            f"Message 2:   {message_2}",
            f"Signature 1: {signature_1}",
            f"Signature 2: {signature_2}",
        ]

        assert (
            TestQ1.sender.verify_schnorr_signature(message_1, signature_1)
            and TestQ1.sender.verify_schnorr_signature(message_2, signature_2)
            and not TestQ1.sender.verify_schnorr_signature(message_2, signature_1)
            and not TestQ1.sender.verify_schnorr_signature(message_1, signature_2)
        ), "ZpStar: El test signatures falla."

        case.set_correct()

    def test_fixed_signatures(self):
        case = RESULTS["test_fixed_signatures_zpstar"]
        receiver = TestQ1.notebook.SecretKeyHolder(TestQ1.group, TestQ1.generator, TestQ1.order)
        receiver.secret_key = 1785520638739734098737227118474597531102242928882915888751831012354271655596608478516084768891616866272919536393716756715709634645379999215356600122406266241614918793699548013731152040030979902196249171745089878229922119373253915355288950590645953179092200524183746804546641507126484917492618746469989952096037778344640889709862006939142477889218589798321257519699596743848766151326269880647255587090355192102417815069501899089121254297103134726458284350732410681593794406176368453357797838100668081595997191186145664187663505003772326536755484591814534230775999474357073329566104102275733031102819494172275687711585589058666046048334459576511559220421770899264450771742066464064738571346523737976797476624175962299137988075769406452936769745174347055456784111664270936389554001770601114872199421984397598050984058066238473435615670968234753526275197324670026642461860988614474914473382242676004920602092635829001706883008235
        receiver.public_key = (
            TestQ1.group,
            TestQ1.generator,
            TestQ1.order,
            TestQ1.generator**receiver.secret_key,
        )
        sender = TestQ1.notebook.PublicKeyHolder(receiver.get_public_key())

        message_1 = 87487239487657402390845345445537575535245362636359843474874982675847795654983644345465672
        message_2 = 342356423654768673454784758475655675968607960898908028328130823908055738944739483282349483044

        signature_1 = (
            106288277326165761843569262860185019571592487210527596339624790318909383314368,
            705331229827156372532716646028278791035648771280402685530377812506975594377994388060595257062082315072197502849736319041746776206338796124522581421903331500662466266644110178654988618937298446649036106393063699485097615895502928978967533479130931403143048792624440377353613984168075225602125329038308289116196292258498989314665870797030843561816780010537028684922665124952041995646627289580018119418865428218905297158775309976976628511339191119398405098400604467328837690085501145393127388321404870322716450676683355345609329750795682179399300322635358700424089828277711037496347121143477647625269126492667384157448203556415186810891952443835349021359445442796247832189722327106721872352790934056167071688303409565530530504762053439150851431160121594690021378842938149557732272575231762520240372445988921768171755112555134554080693675847417558305444296659139928112102218316471046238751471239276586509800922280594884900896426,
        )
        signature_2 = (
            33992219382347423363264494600880972257015240671442667033836250581058592382374,
            2191531925221427037563980935674253872934392969055268522391724289931390770511732493215951549908463942083898880211424219573236000549761772142347603245086288645198472139101753612263625441116035657043583938582972131480916242393385227941661726088450607020657703431182110244348061372386416647641732169000136031278223010304875575466807873923565266452695161868910989868949900134886299412641746589083442640490155429366401579972277923366889908451007546868063777097954622052687314853013523763108538222583364468239595214746415568938731139777688117825105186524736218900595646422485742736963809762604478989518283469530058540713494084561129900121180867097368993270014125604223346423169379478115947426607651141133399752263236817114696654730269668159436922013755247567460597016886844382465467484217097443720415221665357057982794138577378378626176682551682815398877005432911550470751549366114071588315661160297431196652812075990936939994945615,
        )

        case.inputs = [
            "m1 con s1, m2 con s2, m1 NO con s2, m2 NO con s1",
            f"Secret key: {receiver.secret_key}",
            f"Message 1: {message_1}",
            f"Message 2: {message_2}",
            f"Signature 1: {signature_1}",
            f"Signature 2: {signature_2}",
        ]

        assert (
            sender.verify_schnorr_signature(message_1, signature_1)
            and sender.verify_schnorr_signature(message_2, signature_2)
            and not sender.verify_schnorr_signature(message_1, signature_2)
            and not sender.verify_schnorr_signature(message_2, signature_1)
        ), "ZpStar: El test fixed_signatures falla."

        case.set_correct()


class TestQ2:
    p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
    A = 115792089210356248762697446949407573530086143415290314195533631308867097853948
    B = 41058363725152142129326129780047268409114441015993725554835256314039467401291
    g_x = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    g_y = 36134250956749795798585127919587881956611106672985015071877198253568414405109
    order = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    notebook = importlib.import_module("ipynb.fs.full." + PATH)

    INIT_RAISED_ERROR = False

    try:
        group = notebook.EllipticCurve(A, B, p)
        generator = group.get_element(g_x, g_y)
        receiver = notebook.SecretKeyHolder(group, generator, order)
        sender = notebook.PublicKeyHolder(receiver.get_public_key())
    except Exception as e:
        print(e)
        print("Error al cargar la clase EllipticCurve / Holders.")
        INIT_RAISED_ERROR = True

    def _is_sqrt(a, p):
        if a % p == 0:
            return True
        elif pow(a, (p - 1) // 2, p) == 1:
            return True
        return False

    def _sqrt_prime(a, p):
        if a % p == 0:
            return 0
        elif not TestQ2._is_sqrt(a, p):
            raise Exception(f"{a} does not have a square root in module {p}")
        gamma = 1
        while TestQ2._is_sqrt(gamma, p):
            gamma = random.randint(2, p - 1)
        t = 0
        while (p - 1) % pow(2, t + 1) == 0:
            t += 1
        s = (p - 1) // pow(2, t)
        K = []
        i = 2
        while i <= t:
            value = pow(a, pow(2, t - i) * s, p)
            for j in range(0, len(K)):
                value = (value * pow(gamma, pow(2, t - i + j + 1) * s * K[j], p)) % p
            if value == 1:
                K.append(0)
            else:
                K.append(1)
            i += 1
        raiz = pow(a, (s + 1) // 2, p)
        for j in range(0, len(K)):
            raiz = (raiz * pow(gamma, K[j] * s * pow(2, j), p)) % p
        return raiz

    def _generate_message():
        message_x = random.randint(0, TestQ2.p - 1)
        while not TestQ2._is_sqrt(
            (pow(message_x, 3) + TestQ2.A * message_x + TestQ2.B) % TestQ2.p,
            TestQ2.p,
        ):
            message_x = random.randint(0, TestQ2.p - 1)
        message_y = TestQ2._sqrt_prime(
            (pow(message_x, 3) + TestQ2.A * message_x + TestQ2.B) % TestQ2.p,
            TestQ2.p,
        )
        return TestQ2.group.get_element(message_x, message_y)

    def test_order_identity(self):
        case = RESULTS["test_order_identity_elliptic"]

        case.inputs = [
            "Se instancia correctamente con el orden y el identity",
            f"Generator: {TestQ2.generator}",
            f"Order: {TestQ2.order}",
            f"Identity: {TestQ2.group.get_identity()}",
        ]

        assert (
            TestQ2.generator**TestQ2.order == TestQ2.group.get_identity()
        ), "Elliptic Curve: El test order_identity falla."

        case.set_correct()

    def test_order_not_prime(self):
        case = RESULTS["test_order_not_prime_elliptic"]
        order = 1157920892103562487626974469494075735999695522413576034422259061068512044369

        case.inputs = [
            "Instanciar con order no primo debería fallar",
            f"Generator: {TestQ2.generator}",
            f"Order: {order}",
            f"Identity: {TestQ2.group.get_identity()}",
        ]

        with pytest.raises(Exception):
            TestQ2.notebook.SecretKeyHolder(TestQ2.group, TestQ2.generator, order)

        case.set_correct()

    def test_incorrect_point(self):
        case = RESULTS["test_incorrect_point_elliptic"]
        message_x = 8584884342863516615406165511406323351118960803751730059471035603840445150962
        message_y = 98909719646589390956366800466550261365057590657394075725444138176993443443851

        case.inputs = [
            "Punto (x,y) que no pertenece a la curva",
            f"Message_x: {message_x}",
            f"Message_y: {message_y}",
            f"Generator: {TestQ2.generator}",
            f"Order: {TestQ2.order}",
        ]

        with pytest.raises(Exception):
            TestQ2.group.get_element(message_x, message_y)

        case.set_correct()

    def test_distinct_encrypt(self):
        case = RESULTS["test_distinct_encrypt_elliptic"]
        plaintext = TestQ2._generate_message()
        ciphertext_1 = TestQ2.sender.encrypt(plaintext)
        ciphertext_2 = TestQ2.sender.encrypt(plaintext)

        case.inputs = [
            "Ciphertext_1 == Ciphertext_2, para un mismo plaintext",
            f"Plaintext: {plaintext}",
            f"Ciphertext_1: {cipher_to_str(ciphertext_1)}",
            f"Ciphertext_2: {cipher_to_str(ciphertext_2)}",
        ]

        assert not ciphertext_1 == ciphertext_2, "Elliptic Curve: El test distinct_encrypt falla."

        case.set_correct()

    def test_encrypt_decrypt(self):
        case = RESULTS["test_encrypt_decrypt_elliptic"]
        plaintext = TestQ2._generate_message()
        ciphertext = TestQ2.sender.encrypt(plaintext)

        case.inputs = [
            "Plaintext == Decrypt(Ciphertext)",
            f"Plaintext: {plaintext}",
            f"Ciphertext: {cipher_to_str(ciphertext)}",
        ]

        assert plaintext == TestQ2.receiver.decrypt(
            ciphertext
        ), "Elliptic Curve: El test encrypt_decrypt falla."

        case.set_correct()

    def test_signatures(self):
        case = RESULTS["test_signatures_elliptic"]
        message_1 = TestQ2._generate_message()
        message_2 = TestQ2._generate_message()
        signature_1 = TestQ2.receiver.schnorr_signature(message_1)
        signature_2 = TestQ2.receiver.schnorr_signature(message_2)

        case.inputs = [
            "m1 con s1, m2 con s2, m1 NO con s2, m2 NO con s1",
            f"Message_1: {message_1}",
            f"Message_2: {message_2}",
            f"Signature_1: {signature_1}",
            f"Signature_2: {signature_2}",
        ]

        assert (
            TestQ2.sender.verify_schnorr_signature(message_1, signature_1)
            and TestQ2.sender.verify_schnorr_signature(message_2, signature_2)
            and not TestQ2.sender.verify_schnorr_signature(message_1, signature_2)
            and not TestQ2.sender.verify_schnorr_signature(message_2, signature_1)
        ), "Elliptic Curve: El test signatures falla."

        case.set_correct()

    def test_fixed_signatures(self):
        case = RESULTS["test_fixed_signatures_elliptic"]

        receiver = TestQ2.notebook.SecretKeyHolder(TestQ2.group, TestQ2.generator, TestQ2.order)
        receiver.secret_key = (
            70356421495684926937876466808719853649892785673198267186953811513642829862421
        )
        receiver.public_key = (
            TestQ2.group,
            TestQ2.generator,
            TestQ2.order,
            TestQ2.generator**receiver.secret_key,
        )
        sender = TestQ2.notebook.PublicKeyHolder(receiver.get_public_key())

        message_x_1 = 76649984980555424634884504804763288158516615548348238199529385011237269059655
        message_y_1 = 21104261356503354155088464026807043243254738187722405474904399933682671184127
        message_1 = TestQ2.group.get_element(message_x_1, message_y_1)

        message_x_2 = 37151822412953665499932049518405876648757871402573110402850250804141190423032
        message_y_2 = 22536693846859314636150386227033125968516523016443065800020773700626955747569
        message_2 = TestQ2.group.get_element(message_x_2, message_y_2)

        signature_1 = (
            23338523114811393118653330746019059116363514042563338511174461701416051934615,
            115358941752066948439067147778163947175873045835240836064474917173919855484482,
        )
        signature_2 = (
            49535133630393081769555281609884359135035858765993874328335282315374790161662,
            7127942716994367277277029904519466391708184664980418935383123510308948422376,
        )

        case.inputs = [
            "m1 con s1, m2 con s2, m1 NO con s2, m2 NO con s1",
            f"Message_x_1: {message_x_1}",
            f"Message_y_1: {message_y_1}",
            f"Message_x_2: {message_x_2}",
            f"Message_y_2: {message_y_2}",
            f"Signature_1: {signature_1}",
            f"Signature_2: {signature_2}",
        ]

        assert (
            sender.verify_schnorr_signature(message_1, signature_1)
            and sender.verify_schnorr_signature(message_2, signature_2)
            and not sender.verify_schnorr_signature(message_1, signature_2)
            and not sender.verify_schnorr_signature(message_2, signature_1)
        ), "Elliptic Curve: El test fixed_signatures falla."

        case.set_correct()
