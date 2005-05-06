# just prints the digest of the first command line param

import md5daap
from sys import argv
print(md5daap.new(argv[1]).hexdigest())
