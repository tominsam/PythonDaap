#!/usr/bin/python
from cmd import Cmd
from daap import DAAPClient
import sys
import re

# darwin doesn't ship with readline!?
try: import readline
except: pass

class ItShell(Cmd):
    intro = """
    The python/daap interactive shell.
    Type 'help' for help.
    """

    def preloop(self):
        self.prompt = "(no server): "
        self.session = None
        self.database = None

    def emptyline(self):
        pass

    def do_EOF(self, other):
        self.do_exit(other)
        
    def do_exit(self, other):
        """
        exit - Quits. Duh.
        """
        print "bye."
        sys.exit(0)

    def do_connect(self, spec):
        """
        connect [<server> [<port>] ]
        Connects to the give server/port. Defaults to localhost.
        """
        if len(spec) == 0:
            server = "localhost"
            port = 3689
        elif spec.count(" ") == 0:
            server = spec
            port = 3689
        elif spec.count(" ") == 1:
            (server, port) = spec.split(" ")
        else:
            print "Need server and port"
            return

        print "Connecting to %s:%s"%(repr(server), repr(port))
        client = DAAPClient()
        client.connect(server, port)
        self.session = client.login()
        self.do_database( self.session.library().id )
        self.prompt = "(%s:%s): "%(server,port)

    def do_databases(self, other):
        """
        Lists the databases of the connected server
        """
        if not self.session:
            print "Not connected"
            return
        databases = self.session.databases()
        for d in databases:
            print "%s: %s"%(d.id, repr(d.name))

    def do_database(self, id):
        """
        database <id> - use a particular database
        """
        if not self.session:
            print "Not connected"
            return
        databases = self.session.databases()
        for d in databases:
            if str(d.id) == str(id):
                self.database = d
                print "using database '%s'"%repr(d.name)
                self.get_tracks(reset = 1)
                print "Got %s tracks"%len(self._tracks)
                return

        print "No such database"

    def do_playlists(self, other):
        """
        Lists the playlists of the selected database
        """
        if not self.database:
            print "No current database"
            return
        playlists = self.database.playlists()
        print "%s playlists in the selected database."%len(playlists)
        for p in playlists:
            print "%s: %s"%(p.id, repr(p.name))

    def do_playlist(self, id):
        """
        playlist <id> - use a particular playlist
        """
        if not self.session:
            print "Not connected"
            return
        if not self.database:
            print "No current database"
            return
        playlists = self.database.playlists()
        for p in playlists:
            if str(p.id) == str(id):
                self.database = p
                print "using playlist '%s'"%repr(p.name)
                self._tracks = p.tracks()
                print "Got %s tracks"%len(self._tracks)
                return

        print "No such database"

    def get_tracks(self, reset = 0):
        if reset or "_tracks" not in self.__dict__:
            self._tracks = self.database.tracks()
        return self._tracks


    def do_tracks(self, other):
        """tracks - list tracks in the selected database"""
        if not self.database:
            print "No current database"
            return
        tracks = self.get_tracks()
        print "%s tracks in the selected database."%len(tracks)
        if len(tracks) > 50: print "displaying 1-50"
        for t in tracks[:50]:
            print "%s: %s - %s - %s"%(t.id, repr(t.artist), repr(t.album), repr(t.name))

    def do_search(self, other):
        """search <term> - list all tracks matching the given term"""
        if not self.database:
            print "No current database"
            return
        tracks = self.get_tracks()

        found = []
        for t in tracks:
            # TODO - wow, what a hacky search
            if re.search(other, "%s %s %s"%(t.name, t.artist, t.album), re.IGNORECASE ):
                found.append( t )

        print "%s tracks found."%len(found)
        if len(found) > 50: print "displaying 1-50"
        for t in found[:50]:
            print "%s: %s - %s - %s"%(t.id, repr(t.artist), repr(t.album), repr(t.name))
        
    
    def do_download(self, spec):
        """download <track id> [<filename>] - download the given track to the local machine"""
        if not self.database:
            print "No current database"
            return

        if len(spec) == 0:
            print "Need a track id"
            return
        elif spec.count(" ") == 0:
            id = spec
            filename = None
        elif spec.count(" ") == 1:
            (id, filename) = spec.split(" ")
        else:
            print "Need track id and filename only"
            return

        tracks = self.get_tracks()
        for t in tracks:
            if str(t.id) == id:
                if filename == None:
                    filename = "%s - %s.%s"%(repr(t.artist), repr(t.name), t.type)
                t.save( filename )
                return
        print "No such track"



try:
    import logging
    logging.basicConfig(level=logging.DEBUG,
            format='%(asctime)s %(levelname)s %(message)s')
    # run the shell
    shell = ItShell()
    #shell.do_connect("")
    shell.cmdloop()
finally:
    if shell and shell.session:
        shell.session.logout()
