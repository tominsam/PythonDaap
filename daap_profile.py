#!/usr/bin/env python

import sys
import optparse
import hotshot
import hotshot.stats

from daap import DAAPClient

def main():

    prof = hotshot.Profile('daap.prof')
    connection  = DAAPClient()

    # I'm new to this python thing. There's got to be a better idiom
    # for this.
    try: host = sys.argv[1]
    except IndexError: host = "localhost"
    try: port = sys.argv[2]
    except IndexError: port = 3689

    try:
        # do everything in a big try, so we can disconnect at the end
        
        connection.connect( host, port )

        # auth isn't supported yet. Just log in
        session     = connection.login()

        prof.start()

        library = session.library()
        tracks = library.tracks()

    finally:
        # this here, so we logout even if there's an error somewhere,
        # or itunes will eventually refuse more connections.
        try:
            session.logout()
        except Exception: pass

        # save profiling data
        prof.stop()
        prof.close()

    # load profile data and print out stats
    stats = hotshot.stats.load("daap.prof")
    stats.print_stats()

if __name__ == '__main__':
    main()
