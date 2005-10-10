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

# cStringIO is faster, but not subclassable
#from StringIO import StringIO
from cStringIO import StringIO

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
        return
    for object in treeroot.contains:
        # each item should be one of two things
        # a status code, or a dictionary
        if object.codeName() == 'dmap.status':
            pass
        elif object.codeName() == 'dmap.dictionary':
            code    = None
            name    = None
            dtype   = None
            # a dictionary object should contain three items:
            # a 'dmap.contentcodesnumber' the 4 letter content code
            # a 'dmap.contentcodesname' the name of the code
            # a 'dmap.contentcodestype' the type of the code
            for info in object.contains:
                if info.codeName() == 'dmap.contentcodesnumber':
                    code    = info.value
                elif info.codeName() == 'dmap.contentcodesname':
                    name    = info.value
                elif info.codeName() == 'dmap.contentcodestype':
                    try:
                        dtype   = dmapDataTypes[info.value]
                    except:
                        print 'DEBUG: DAAPParseCodeTypes: unknown data type %s for code %s, defaulting to s' % (info.value, name)
                        dtype   = 's'
                else:
                    raise DAAPError('DAAPParseCodeTypes: unexpected code %s at level 2' % info.codeName())
            if code == None or name == None or dtype == None:
                print 'DEBUG: DAAPParseCodeTypes: missing information, not adding entry'
            else:
                try:
                    dtype = dmapFudgeDataTypes[name]
                except: pass

                dmapCodeTypes[code] = (name, dtype)
        else:
            raise DAAPError('DAAPParseCodeTypes: unexpected code %s at level 1' % info.codeName())

class DAAPError(Exception): pass

class DAAPObject:
    def __init__(self):
        self.code   = None
        self.length = None
        self.value  = None
        self.contains   = []

    def getAtom(self, code):
        """returns an atom of the given code by searching 'contains' recursively."""
        if self.code == code:
            if self.objectType() == 'c':
                return self
            return self.value

        # ok, it's not us. check our children
        for object in self.contains:
            value = object.getAtom(code)
            if value: return value
        return None

        
    def codeName(self):
        if self.code == None or not dmapCodeTypes.has_key(self.code):
            return None
        else:
            return dmapCodeTypes[self.code][0]

    def objectType(self):
        if self.code == None or not dmapCodeTypes.has_key(self.code):
            return None
        else:
            return dmapCodeTypes[self.code][1]

    def printTree(self, level = 0):
        print '\t' * level, '%s (%s)\t%s\t%s' % (self.codeName(), self.code, self.objectType(), str(self.value))
        for object in self.contains:
            object.printTree(level + 1)

    def encode(self):
        # generate DMAP tagged data format
        # step 1 - find out what type of object we are
        type    = self.objectType()
        if type == 'c':
            # our object is a container,
            # this means we're going to have to
            # check contains[]
            value   = ''
            for item in self.contains:
                # get the data stream from each of the sub elements
                value += item.encode()
            # get the length of the data
            length  = len(value)
            # pack: 4 byte code, 4 byte length, length bytes of value
            data    = struct.pack('!4sI%ss' % length, self.code, length, value)
            return data
            
        elif type == 'v':
            # packing a version tag is about 1 point different to everything
            # below, but it means it won't fit into our abstract packing
            value   = self.value.split('.')
            length  = struct.calcsize('!HH')
            data    = struct.pack('!4sIHH', self.code, length, value[0], value[1])
            return data
        else:
            # we don't have to traverse anything
            # to calculate the length and such
            # we want to encode the contents of
            # value for our value
            if type == 'l':
                packing = 'q'
            elif type == 'ul':
                packing = 'Q'
            elif type == 'i':
                packing = 'i'
            elif type == 'ui':
                packing = 'I'
            elif type == 'h':
                packing = 'h'
            elif type == 'uh':
                packing = 'H'
            elif type == 'b':
                packing = 'b'
            elif type == 'ub':
                packing = 'B'
            elif type == 't':
                packing = 'I'
            elif type == 's':
                packing = '%ss' % len(self.value)
            else:
                raise DAAPError('DAAPObject: encode: unknown code %s' % self.code)
                return
            # calculate the length of what we're packing
            length  = struct.calcsize('!%s' % packing)
            # pack: 4 characters for the code, 4 bytes for the length, and 'length' bytes for the value
            data    = struct.pack('!4sI%s' % packing, self.code, length, self.value)
            return data
        
    def processData(self, str):

        # first we need 4 bytes for the code
        self.code   = str.read(4)

        # now we need the length of the objects data
        # this is another 4 bytes
        code = str.read(4)
        self.length = struct.unpack('!I', code)[0]

        # now we need to find out what type of object it is
        type        = self.objectType()
        
        # TODO - I don't like this read() here. Ideally, we'd only ever
        # have one StringIO object floating around, passing it to our
        # children, who would keep eating off the front of it, until
        # eventually we hit the end, at which point we'd be done. This
        # copy must be slowing us down...
        start_pos = str.tell()

        if type == 'c':
            # the object is a container, we need to pass it
            # it's length amount of data for processessing
            while str.tell() < start_pos + self.length:
                object  = DAAPObject()
                self.contains.append(object)
                object.processData(str)

            return


        # not a container, we're a single atom. Read it.
        code = str.read(self.length)

        if type == 'l':
            # the object is a long long number,
            self.value  = struct.unpack('!q', code)[0]
        elif type == 'ul':
            # the object is an unsigned long long
            self.value  = struct.unpack('!Q', code)[0]
        elif type == 'i':
            # the object is a number,
            self.value  = struct.unpack('!i', code)[0]
        elif type == 'ui':
            # unsigned integer
            self.value  = struct.unpack('!I', code)[0]
        elif type == 'h':
            # this is a short number,
            self.value  = struct.unpack('!h', code)[0]
        elif type == 'uh':
            # unsigned short
            self.value  = struct.unpack('!H', code)[0]
        elif type == 'b':
            # this is a byte long number
            self.value  = struct.unpack('!b', code)[0]
        elif type == 'ub':
            # unsigned byte
            self.value  = struct.unpack('!B', code)[0]
        elif type == 'v':
            # this is a version tag
            self.value  = float("%s.%s" % struct.unpack('!HH', code))
        elif type == 't':
            # this is a time string
            self.value  = struct.unpack('!I', code)[0]
        elif type == 's':
            # the object is a string
            # we need to read length characters from the string
            try:
                self.value  = unicode(
                    struct.unpack('!%ss' % self.length, code)[0], 'utf-8')
            except UnicodeDecodeError:
                # oh, urgh
                self.value = unicode(
                    struct.unpack('!%ss' % self.length, code)[0], 'latin-1')
        else:
            # we don't know what to do with this object
            # put it's raw data into value
            print 'DEBUG: DAAPObject: Unknown code %s for type %s, writing raw data'%(code, self.code)
            self.value  = code


class DAAPClient:
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

        # this 'first' thing is a nasty hack. There should be a better python
        # idiom for it. I'd use map in perl.
        first = 1
        for key in params:
            if first: r += "?"
            else: r += "&"
            first = 0
            r += "%s=%s"%(key, params[key])

        print("DEBUG: getting %s"%r)

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
        
    def request(self, r, params = {}, answers = 1):
        """Make a request to the DAAP server, with the passed params. This
        deals with all the cikiness like validation hashes, etc, etc"""

        # this returns an HTTP response object
        response    = self._get_response(r, params)
        status = response.status
        content = response.read()
        # if we got gzipped data base, gunzip it.
        if response.getheader("Content-Encoding") == "gzip":
            print "DEBUG: gunzipping data"
            old_len = len(content)
            compressedstream = StringIO( content )
            gunzipper = gzip.GzipFile(fileobj=compressedstream)
            content = gunzipper.read()
            print "DEBUG: expanded from %s bytes to %s bytes"%(old_len, len(content))
        # close this, we're done with it
        response.close()
        
        #print "DEBUG: DAAPClient: response status is %s"%response.status
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

        return self.readResponse( content )

    def readResponse(self, data):
        """Convert binary response from a request to a DAAPObject"""
        str = StringIO(data)
        object  = DAAPObject()
        object.processData(str)
        return object


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
            print 'DEBUG: DAAPClient: login unable to determine session ID'
            return
        print "DEBUG: Logged in as session %s"%sessionid
        return DAAPSession(self, sessionid)


class DAAPSession:

    def __init__(self, connection, sessionid):
        self.connection = connection
        self.sessionid  = sessionid
        self.revision   = 1

    def request(self, r, params = {}, answers = 1):
        """Pass the request through to the connection, adding the session-id
        parameter."""
        params['session-id'] = self.sessionid
        return self.connection.request(r, params, answers)

    def update(self):
        response = self.request("/update")
        #response.printTree()

    def databases(self):
        response = self.request("/databases")
        db_list = response.getAtom("mlcl").contains
        return map( lambda d: DAAPDatabase(self, d), db_list )
        
    def library(self):
        # there's only ever one db, and it's always the library...
        return self.databases()[0]

    def logout(self):
        response = self.request("/logout")
        print 'DEBUG: DAAPSession: expired session id %s' % self.sessionid
        
    def __del__(self):
        print "DEBUG: destroying session"
        self.logout()

class DAAPDatabase:

    def __init__(self, session, atom):
        self.session = session
        self.name = atom.getAtom("minm")
        self.id = atom.getAtom("miid")

    def tracks(self):
        """returns all the tracks in this database, as DAAPTrack objects"""
        response = self.session.request("/databases/%s/items"%self.id, {
            'meta':"dmap.itemid,dmap.itemname,dmap.persistentid,daap.songalbum,daap.songartist,daap.songformat,daap.songsize,daap.songbitrate,daap.songsamplerate,daap.songstarttime,daap.songstoptime,daap.songtime"
        })
        track_list = response.getAtom("mlcl").contains
        return map( lambda t: DAAPTrack(self, t), track_list )

    def playlists(self):
        response = self.session.request("/databases/%s/containers"%self.id)
        db_list = response.getAtom("mlcl").contains
        return map( lambda d: DAAPPlaylist(self, d), db_list )


class DAAPPlaylist:

    def __init__(self, database, atom):
        self.database = database
        self.id = atom.getAtom("miid")
        self.name = atom.getAtom("minm")
        self.count = atom.getAtom("mimc")

    def tracks(self):
        """returns all the tracks in this playlist, as DAAPTrack objects"""
        response = self.database.session.request("/databases/%s/containers/%s/items"%(self.database.id,self.id), {
            'meta':"dmap.itemid,dmap.itemname,dmap.persistentid,daap.songalbum,daap.songartist,daap.songformat,daap.songsize,daap.songbitrate,daap.songsamplerate,daap.songstarttime,daap.songstoptime,daap.songtime"
        })
        track_list = response.getAtom("mlcl").contains
        return map( lambda t: DAAPTrack(self.database, t), track_list )


class DAAPTrack:

    def __init__(self, database, atom):
        self.atom = atom
        self.database = database
        self.name = atom.getAtom("minm")
        self.artist = atom.getAtom("asar")
        self.album = atom.getAtom("asal")
        self.id = atom.getAtom("miid")
        self.type = atom.getAtom("asfm")
        self.time = atom.getAtom("astm")
        self.size = 0
        #atom.printTree()

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
        print "saving to '%s'"%filename
        mp3 = open(filename, "w")
        r = self.request()
        # doing this all on one lump seems to explode a lot. TODO - what
        # is a good block size here?
        data = r.read(32 * 1024)
        while (data):
          mp3.write(data)
          data = r.read(32 * 1024)
        mp3.close()
        r.close()
        print "Done"


if __name__ == '__main__':
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

        library = session.library()
        print "Library name is '%s'"%repr(library.name)

        tracks = library.tracks()

        # demo - save the first track to disk
        #print("Saving %s by %s to disk as 'track.mp3'"%(tracks[0].name, tracks[0].artist))
        #tracks[0].save("track.mp3")

        tracks[0].atom.printTree()


    finally:
        # this here, so we logout even if there's an error somewhere,
        # or itunes will eventually refuse more connections.
        print "--------------"
        try:
            session.logout()
        except Exception: pass
