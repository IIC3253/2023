import os
from config import BASE_PATH, RESULTS_PATH
from argparse import ArgumentParser
from threading import Thread

x = """
NAME es el nombre del alumno.
PATH es la ruta de la carpeta del alumno.
Ejemplo de path: carpeta_alumno/Pregunta_1/pregunta1.ipynb
"""

parser = ArgumentParser(description=x)
parser.add_argument("-n", "--name")
parser.add_argument("-p", "--path")

with open("errors.txt", "w") as f:
    pass


def execute_test(alumno, path):
    print(f"Testing {alumno} in {path}")
    print(f"pytest -s --capture=no test_t3.py --name {alumno} --path {path}")
    os.system(f"pytest -s --capture=no test_t3.py --name {alumno} --path {path}")


def execute_thread(alumnos):
    for alumno in alumnos:
        PATH = os.path.join(BASE_PATH, alumno, "Pregunta_1", "pregunta1.ipynb")
        if not os.path.isfile(PATH):
            with open("errors.txt", "a") as f:
                f.write(f"El alumno {alumno} no tiene el archivo pregunta1.ipynb\n")
                continue

        execute_test(alumno, PATH)


def test_dirs():
    _alumnos = os.listdir(BASE_PATH)

    already_tested = os.listdir(RESULTS_PATH)
    already_tested = [x.replace(".txt", "") for x in already_tested]

    _alumnos = list(set(_alumnos) - set(already_tested))

    # divide alumnos in 4
    alumnos_div = [_alumnos[i::4] for i in range(4)]

    for alumnos_subdiv in alumnos_div:
        thread = Thread(target=execute_thread, args=(alumnos_subdiv,))
        thread.start()


if __name__ == "__main__":
    args = parser.parse_args()
    if args.name and args.path:
        print()
        execute_test(args.name, args.path)
    else:
        input("¿Ejecutar para todos los alumnos? (Enter) ")
        test_dirs()
