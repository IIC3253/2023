import os

BASE_PATH = "codigos"
RESULTS_PATH = "resultados"
assert os.path.isdir(RESULTS_PATH), f"No existe el directorio '{RESULTS_PATH}'"
assert os.path.isdir(
    BASE_PATH
), f"No existe el directorio '{BASE_PATH}', lo debes cambiar a tu nombre (donde están tus notebooks)"


alumnos = os.listdir(BASE_PATH)
