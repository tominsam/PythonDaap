from distutils.core import setup, Extension

setup (
  name = "PythonDaap",
  version = "0.6",
  author = "Tom Insam",
  author_email = "tom@jerakeen.org",
  url = "http://jerakeen.org/code/pythondaap",
  description = "a python daap client library",
  py_modules = ['daap'],
  ext_modules = [Extension('md5daap',sources=['md5module.c', 'md5c.c'])]
)
