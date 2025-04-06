from setuptools import setup
from Cython.Build import cythonize

setup(ext_modules=cythonize(["utils.py", "GUI.py", "data_storage.py"]))
