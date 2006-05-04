# daap.py
#
# DAAP classes and methods.
#
# original work (c) 2004, Davyd Madeley <davyd@ucc.asn.au>
#
# Later iTunes authentication work and object model
# copyright 2005 Tom Insam <tom@jerakeen.org>
#

import httplib, struct, sys
import md5, md5daap
import gzip
import logging
from urllib import urlencode
from cStringIO import StringIO

__all__ = ['DAAPError', 'DAAPObject', 'DAAPClient', 'DAAPSession', 'DAAPDatabase', 'DAAPPlaylist', 'DAAPTrack']

log = logging.getLogger('daap')

# the itunes authentication hasher
seed_v2 = []
for i in (range(255)):
    ctx = md5.new()
    if (i & 0x80): ctx.update("Accept-Language")
    else:          ctx.update("user-agent")

    if (i & 0x40): ctx.update("max-age")
    else:          ctx.update("Authorization")

    if (i & 0x20): ctx.update("Client-DAAP-Version")
    else:          ctx.update("Accept-Encoding")

    if (i & 0x10): ctx.update("daap.protocolversion")
    else:          ctx.update("daap.songartist")

    if (i & 0x08): ctx.update("daap.songcomposer")
    else:          ctx.update("daap.songdatemodified")

    if (i & 0x04): ctx.update("daap.songdiscnumber")
    else:          ctx.update("daap.songdisabled")

    if (i & 0x02): ctx.update("playlist-item-spec")
    else:          ctx.update("revision-number")

    if (i & 0x01): ctx.update("session-id")
    else:          ctx.update("content-codes")

    seed_v2.append( ctx.hexdigest().upper() )

# this is a translation of the GenerateHash function in hasher.c of
# libopendaap http://crazney.net/programs/itunes/authentication.html
seed_v3 = []
for i in (range(255)):
    ctx = md5daap.new()

    if (i & 0x40): ctx.update("eqwsdxcqwesdc")
    else:          ctx.update("op[;lm,piojkmn")

    if (i & 0x20): ctx.update("876trfvb 34rtgbvc")
    else:          ctx.update("=-0ol.,m3ewrdfv")

    if (i & 0x10): ctx.update("87654323e4rgbv ")
    else:          ctx.update("1535753690868867974342659792")

    if (i & 0x08): ctx.update("Song Name")
    else:          ctx.update("DAAP-CLIENT-ID:")

    if (i & 0x04): ctx.update("111222333444555")
    else:          ctx.update("4089961010")

    if (i & 0x02): ctx.update("playlist-item-spec")
    else:          ctx.update("revision-number")

    if (i & 0x01): ctx.update("session-id")
    else:          ctx.update("content-codes")

    if (i & 0x80): ctx.update("IUYHGFDCXWEDFGHN")
    else:          ctx.update("iuytgfdxwerfghjm")

    seed_v3.append( ctx.hexdigest().upper() )

def hash_v2(url, select):
    ctx = md5.new()
    ctx.update( url )
    ctx.update( "Copyright 2003 Apple Computer, Inc." )
    ctx.update( seed_v2[ select ])
    return ctx.hexdigest().upper()

def hash_v3(url, select, sequence = 0):
    ctx = md5daap.new()
    ctx.update( url )
    ctx.update( "Copyright 2003 Apple Computer, Inc." )
    ctx.update( seed_v3[ select ])
    if sequence > 0: ctx.update( str(sequence) )
    return ctx.hexdigest().upper()



dmapCodeTypes = {
    # these content codes are needed to learn all others
    'mccr':('dmap.contentcodesresponse', 'c'),
    'mstt':('dmap.status', 'ui'),
    'mdcl':('dmap.dictionary', 'c'),
    'mcnm':('dmap.contentcodesnumber', 's'),
    'mcna':('dmap.contentcodesname', 's'),
    'mcty':('dmap.contentcodestype', 'uh'),
        }
dmapDataTypes = {
    # these are the data types
    1:'b',  # byte
    2:'ub', # unsigned byte
    3:'h',  # short
    4:'uh', # unsigned short
    5:'i',  # integer
    6:'ui', # unsigned integer
    7:'l',  # long
    8:'ul', # unsigned long
    9:'s',  # string
    10:'t', # timestamp
    11:'v', # version
    12:'c', # container
        }

dmapFudgeDataTypes = {
  'dmap.authenticationschemes':'1'
}

def DAAPParseCodeTypes(treeroot):
    # the treeroot we are given should be a
    # dmap.contentcodesresponse
    if treeroot.codeName() != 'dmap.contentcodesresponse':
        raise DAAPError("DAAPParseCodeTypes: We cannot generate a dictionary from this tree.")
    
    for code, type, start, length in treeroot.iterAtomsWithCode('mdcl'):
        obj = DAAPObject(buffer(treeroot.buf, start, length))
        if obj.codeName() == 'dmap.dictionary':
            obj.attrmap = {'code':'mcnm', 'name':'mcna', 'type':'mcty'}
            try:
                dtype = dmapDataTypes[obj.type]
            except:
                log.debug('DAAPParseCodeTypes: unknown data type %s for code %s, defaulting to s', obj.type, obj.name)
                dtype   = 's'
            if obj.code == None or obj.name == None or dtype == None:
                log.debug('DAAPParseCodeTypes: missing information, not adding entry')
            else:
                try:
                    dtype = dmapFudgeDataTypes[obj.name]
                except KeyError: pass

                dmapCodeTypes[obj.code] = (obj.name, dtype)

class DAAPError(Exception): pass


class DAAPClient(object):
    def __init__(self):
        self.socket = None
        self.request_id = 0
        self._old_itunes = 0

    def connect(self, hostname, port = 3689):
        if self.socket != None:
            raise DAAPError("DAAPClient: already connected.")
        self.hostname = hostname
        self.port     = port
        self.socket = httplib.HTTPConnection(hostname, port)
        self.getContentCodes() # practically required
        self.getInfo() # to determine the remote server version

    def _get_response(self, r, params = {}, gzip = 1):
        """Makes a request, doing the right thing, returns the raw data"""

        if params:
            r = '%s?%s' % (r, urlencode(params))

        log.debug('getting %s', r)

        headers = {
            'Client-DAAP-Version': '3.0',
            'Client-DAAP-Access-Index': '2',
        }

        if gzip: headers['Accept-encoding'] = 'gzip'

        # TODO - we should allow for different versions of itunes - there
        # are a few different hashing algos we could be using. I need some
        # older versions of iTunes to test against.
        if self.request_id > 0:
            headers[ 'Client-DAAP-Request-ID' ] = self.request_id

        if (self._old_itunes):
            headers[ 'Client-DAAP-Validation' ] = hash_v2(r, 2)
        else:
            headers[ 'Client-DAAP-Validation' ] = hash_v3(r, 2, self.request_id)

        self.socket.request('GET', r, None, headers)

        response    = self.socket.getresponse()
        return response;

    def request(self, r, params = {}, answers = 1, readFunc = None):
        """Make a request to the DAAP server, with the passed params. This
        deals with all the cikiness like validation hashes, etc, etc"""

        # this returns an HTTP response object
        response    = self._get_response(r, params)
        status = response.status
        content = response.read()
        # if we got gzipped data base, gunzip it.
        if response.getheader("Content-Encoding") == "gzip":
            log.debug("gunzipping data")
            old_len = len(content)
            compressedstream = StringIO( content )
            gunzipper = gzip.GzipFile(fileobj=compressedstream)
            content = gunzipper.read()
            log.debug("expanded from %s bytes to %s bytes", old_len, len(content))
        # close this, we're done with it
        response.close()

        if status == 401:
            raise DAAPError('DAAPClient: %s: auth required'%r)
        elif status == 403:
            raise DAAPError('DAAPClient: %s: Authentication failure'%r)
        elif status == 503:
            raise DAAPError('DAAPClient: %s: 503 - probably max connections to server'%r)
        elif status == 204:
            # no content, ie logout messages
            return None
        elif status != 200:
            raise DAAPError('DAAPClient: %s: Error %s making request'%(r, response.status))

        if readFunc == None:
            return self.readResponse( content )
        else:
            return readFunc( content )

    def readResponse(self, data):
        """Convert binary response from a request to a DAAPObject"""
        return DAAPObject(data)

    def getContentCodes(self):
        # make the request for the content codes
        response = self.request('/content-codes')
        # now parse and add this information to the dictionary
        DAAPParseCodeTypes(response)

    def getInfo(self):
        response = self.request('/server-info')

        # detect the 'old' iTunes 4.2 servers, and set a flag, so we use
        # the real MD5 hash algo to verify requests.
        version = response.getAtom("apro")
        if int(version) == 2:
            self._old_itunes = 1

        # response.printTree()

    def login(self):
        response = self.request("/login")
        sessionid   = response.getAtom("mlid")
        if sessionid == None:
            log.debug('DAAPClient: login unable to determine session ID')
            return
        log.debug("Logged in as session %s", sessionid)
        return DAAPSession(self, sessionid)


class DAAPSession(object):

    def __init__(self, connection, sessionid):
        self.connection = connection
        self.sessionid  = sessionid
        self.revision   = 1

    def request(self, r, params = {}, answers = 1, readFunc = None):
        """Pass the request through to the connection, adding the session-id
        parameter."""
        params['session-id'] = self.sessionid
        return self.connection.request(r, params, answers, readFunc)

    def update(self):
        response = self.request("/update")
        #response.printTree()

    def databases(self):
        response = self.request("/databases")
        return [DAAPDatabase(buffer(response.buf, start, length), self) for code, type, start, length in response.iterAtomsWithCode("mlcl")]

    def library(self):
        # there's only ever one db, and it's always the library...
        # TODO: then whats with this stupid code?
        return self.databases()[0]

    def logout(self):
        response = self.request("/logout")
        log.debug('DAAPSession: expired session id %s', self.sessionid)


def decodeData(type, data):
    typeDecodeMap = {'l':'q', 'ul':'Q', 'i':'i', 'ui':'I', 'h':'h', 'uh':'H', 'b':'b', 'ub':'B', 'v':'HH'}
    if type in typeDecodeMap.keys():
        return struct.unpack('!' + typeDecodeMap[type], data)[0]
    elif type == 's':
        # the object is a string
        # we need to read length characters from the string
        try:
            return unicode(struct.unpack('!%ss' % len(data), data)[0], 'utf-8')
        except UnicodeDecodeError:
            # oh, urgh
            return unicode(struct.unpack('!%ss' % len(data), data)[0], 'latin-1')
    else:
        # we don't know what to do with this object
        # put it's raw data into value
        log.debug('DAAPObject: Unknown data %s for type %s, writing raw data', repr(data), type)
        return data


class DAAPObject(object):

    attrmap = {}
    
    def __init__(self, str):
        self.buf = buffer(str)

    def iterAtomsWithCodes(self, codes, p = 0L):
        """only yield atoms with specified codes"""
        for code, type, p, length in self.iterAtoms():
            if code in codes:
                yield code, type, p, length

    def iterAtomsWithCode(self, wcode, p = 0L):
        """only yield atoms with specified code"""
        for code, type, p, length in self.iterAtoms():
            if code == wcode:
                yield code, type, p, length

    def iterAtoms(self, i = 0L, end = 0L):
        """iterate through every atom in the packet.
        yield code, type, start position, length"""
        if end == 0:
            end = len(self.buf)
        while i < end:
            # read 4 bytes for the code and 4 bytes for the length of the objects data
            code, length = struct.unpack('!4sI', self.buf[i:i+8])
            # now we need to find out what type of object it is
            if code == None or not dmapCodeTypes.has_key(code):
                type = None
            else:
                type = dmapCodeTypes[code][1]

            yield code, type, i, length + 8
            i += 8

            if type == 'c':
                for result in self.iterAtoms(i, i + length):
                    yield result
            i += length

    def __getattr__(self, name):
        if self.__dict__.has_key(name):
            return self.__dict__[name]
        elif self.__dict__.has_key('attrmap') and self.__dict__['attrmap'].has_key(name):
            try:
                code, type, start, length = self.iterAtomsWithCode(self.__dict__['attrmap'][name]).next()
                # TODO: why are some mcnm strings and others integers?
                if code == 'mcnm' and type == 'i':
                    type = 's'
                # TODO: what is faster, slice or buffer?
                return decodeData(type, self.buf[start + 8:start + length])
                #return decodeData(type, buffer(self.buf, start + 8, length - 8))
            except StopIteration:
                return None
        elif self.__class__.attrmap.has_key(name):
            try:
                code, type, start, length = self.iterAtomsWithCode(self.__class__.attrmap[name]).next()
                return decodeData(type, self.buf[start + 8:start + length])
                #return decodeData(type, buffer(self.buf, start + 8, length - 8))
            except StopIteration:
                return None

        raise AttributeError, name

    def codeName(self):
        code = struct.unpack('!4s', self.buf[0:4])[0]
        if code == None or not dmapCodeTypes.has_key(code):
            return None
        else:
            return dmapCodeTypes[code][0]

    def getAtom(self, icode):
        try:
            code, type, start, length = self.iterAtomsWithCode(icode).next()
            return decodeData(type, buffer(self.buf, start + 8, length - 8))
        except StopIteration:
            return None

class DAAPTrack(DAAPObject):

    attrmap = {'name':'minm',
        'artist':'asar',
        'album':'asal',
        'id':'miid',
        'type':'asfm',
        'time':'astm',
        'size':'astz'}

    def request(self):
        """returns a 'response' object for the track's mp3 data.
        presumably you can strem from this or something"""

        # gotta bump this every track download
        self.database.session.connection.request_id += 1

        # get the raw response object directly, not the parsed version
        return self.database.session.connection._get_response(
            "/databases/%s/items/%s.%s"%(self.database.id, self.id, self.type),
            { 'session-id':self.database.session.sessionid },
            gzip = 0,
        )

    def save(self, filename):
        """saves the file to 'filename' on the local machine"""
        log.debug("saving to '%s'", filename)
        mp3 = open(filename, "wb")
        r = self.request()
        # doing this all on one lump seems to explode a lot. TODO - what
        # is a good block size here?
        data = r.read(32 * 1024)
        while (data):
          mp3.write(data)
          data = r.read(32 * 1024)
        mp3.close()
        r.close()
        log.debug("Done")


class DAAPDatabase(DAAPObject):

    attrmap = {'name':'minm',
        'id':'miid'}

    def __init__(self, buf, session):
        #super(DAAPObject, self).__init__(buf)
        DAAPObject.__init__(self, buf)
        self.session = session

    def tracks(self):
        """returns all the tracks in this database, as DAAPTrack objects"""
        response = self.session.request("/databases/%s/items"%self.id, {
            'meta':"dmap.itemid,dmap.itemname,daap.songalbum," +
                   "daap.songartist,daap.songformat,daap.songtime"
        #}, 1, self.readResponse)
        }, 1, None)

        for code, type, start, length in response.iterAtomsWithCode('mlit'):
            yield DAAPTrack(buffer(response.buf, start, length))
    
    def playlists(self):
        response = self.session.request("/databases/%s/containers"%self.id)
        db_list = response.getAtom("mlcl").contains
        return [DAAPPlaylist(self, d) for d in db_list]


# TODO: convert this class to new DAAPObject model
class DAAPPlaylist(object):

    def __init__(self, database, atom):
        self.database = database
        self.id = atom.getAtom("miid")
        self.name = atom.getAtom("minm")
        self.count = atom.getAtom("mimc")

    def tracks(self):
        """returns all the tracks in this playlist, as DAAPTrack objects"""
        response = self.database.session.request("/databases/%s/containers/%s/items"%(self.database.id,self.id), {
            'meta':"dmap.itemid,dmap.itemname,daap.songalbum,daap.songartist,"+
                   "daap.songformat,daap.songtime"
        })
        track_list = response.getAtom("mlcl").contains
        return [DAAPTrack(self.database, t) for t in track_list]


if __name__ == '__main__':
    def main():
        connection  = DAAPClient()

        # I'm new to this python thing. There's got to be a better idiom
        # for this.
        try: host = sys.argv[1]
        except IndexError: host = "localhost"
        try: port = sys.argv[2]
        except IndexError: port = 3689

        logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(levelname)s %(message)s')

        try:
            # do everything in a big try, so we can disconnect at the end

            connection.connect( host, port )

            # auth isn't supported yet. Just log in
            session     = connection.login()

            library = session.library()
            log.debug("Library name is '%s'", repr(library.name))

            log.debug('start track list')
            for track in library.tracks():
                track.artist, track.name
            log.debug('end track list')

            # demo - save the first track to disk
            #print("Saving %s by %s to disk as 'track.mp3'"%(tracks[0].name, tracks[0].artist))
            #tracks[0].save("track.mp3")

            #tracks[0].atom.printTree()
            from time import sleep
            sleep(5)

        finally:
            # this here, so we logout even if there's an error somewhere,
            # or itunes will eventually refuse more connections.
            print "--------------"
            try:
                session.logout()
            except Exception: pass

    main()
