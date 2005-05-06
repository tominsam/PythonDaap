from distutils.core import setup, Extension

setup (
  name = "PythonDaap",
  version = "1.0",
  author = "Tom Insam",
  author_email = "tom@jerakeen.org",
  url = "http://jerakeen.org/trac/wiki/PythonDaap",
  description = "a python daap client library",
  py_modules = ['daap'],
  ext_modules = [Extension('md5daap',sources=['md5module.c', 'md5c.c'])]
)
