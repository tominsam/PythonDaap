#
# daap.py
#
# DAAP classes and methods.
#
# (c) 2004, Davyd Madeley <davyd@ucc.asn.au>
#

import httplib, struct

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

def DAAPParseCodeTypes(treeroot):
    # the treeroot we are given should be a
    # dmap.contentcodesresponse
    if treeroot.codeName() != 'dmap.contentcodesresponse':
        print "DEBUG: DAAPParseCodeTypes: We cannot generate a dictionary from this tree."
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
                    print 'DEBUG: DAAPParseCodeTypes: unexpected code %s at level 2' % info.codeName()
            if code == None or name == None or dtype == None:
                print 'DEBUG: DAAPParseCodeTypes: missing information, not adding entry'
            else:
                dmapCodeTypes[code] = (name, dtype)
        else:
            print 'DEBUG: DAAPParseCodeTypes: unexpected code %s at level 1' % info.codeName()

class DAAPObject:
    def __init__(self):
        self.code   = None
        self.length = None
        self.value  = None
        self.contains   = []
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
                print 'DEBUG: DAAPObject: encode: unknown code %s' % self.code
                return
            # calculate the length of what we're packing
            length  = struct.calcsize('!%s' % packing)
            # pack: 4 characters for the code, 4 bytes for the length, and 'length' bytes for the value
            data    = struct.pack('!4sI%s' % packing, self.code, length, self.value)
            return data
        
    def processData(self, data):
        # first we need 4 bytes for the code
        code, data  = data[:4], data[4:]
        self.code   = code
        if self.codeName() == None:
            print 'DEBUG: DAAPObject: unknown code %s' % code
        # now we need the length of the objects data
        # this is another 4 bytes
        code, data  = data[:4], data[4:]
        self.length = struct.unpack('!I', code)[0]
        # now we need to find out what type of object it is
        type        = self.objectType()
        code, data  = data[:self.length], data[self.length:]
        
        if type == 'c':
            # the object is a container, we need to pass it
            # it's length amount of data for processessing
            while len(code) > 0:
                object  = DAAPObject()
                self.contains.append(object)
                code    = object.processData(code)
        elif type == 'l':
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
            self.value  = struct.unpack('!%ss' % self.length, code)[0]
        else:
            # we don't know what to do with this object
            # put it's raw data into value
            print 'DEBUG: DAAPObject: Unknown code, writing raw data'
            self.value  = code

        # return the left over data for further processessing
        return data

class DAAPClient:
    def __init__(self):
        self.socket = None
        self.port   = 3689
        self.headers    = {
#           'Client-DAAP-Version': '2.0',
            'User-Agent': 'pyTunes/0.1 (Linux; N)',
#           'Client-DAAP-Access-Index': '1',
#           'Accept-Language': 'en-au, en-us;q=0.67, en;q=0.33',
#           'Client-DAAP-Validation': 'DEE8EBB183C8F60D1D47B04591BA47E5'
                }
    def connect(self, hostname):
        if self.socket != None:
            print "DEBUG: DAAPClient: already connected."
            return
        self.hostname   = hostname
        self.socket = httplib.HTTPConnection(hostname, self.port)
    def getContentCodes(self):
        # make the request for the content codes
        self.socket.request('GET', '/content-codes', None, self.headers)
        response    = self.socket.getresponse()
        if response.status == 401:
            print 'DEBUG: DAAPClient: getContentCodes: auth required'
        data        = response.read()
        # decode the response
        response    = self.readResponse(data)
        # now parse and add this information to the dictionary
        if len(response) != 1:
            print 'DEBUG: DAAPClient: getContentCodes: wrong number of answers'
            return
        DAAPParseCodeTypes(response[0])
    def getInfo(self):
        self.socket.request('GET', '/server-info', None, self.headers)
        response    = self.socket.getresponse()
        # 'response.status' is the status code of the response
        # 'response.reason' is the reason associtated with response.status
        # 'response.read()' reads data from the body of the reply
        # 'response.msg' is a list of the headers returned
        # 'response.getheader(name)' retrieves the contents of a particular header
        data        = response.read()
        response    = self.readResponse(data)
        if len(response) != 1:
            print 'DEBUG: DAAPClient: getInfo: wrong numner of answers'
            return
        response[0].printTree()
    def login(self):
        self.socket.request('GET', '/login', None, self.headers)
        response    = self.socket.getresponse()
        if response.status == 401:
            print 'DEBUG: DAAPClient: login: auth required'
        data        = response.read()
        response    = self.readResponse(data)
        if len(response) != 1:
            print 'DEBUG: DAAPClient: login: wrong number of answers'
            return
        response[0].printTree()
        sessionid   = None
        for object in response[0].contains:
            if object.codeName() == 'dmap.sessionid':
                sessionid   = object.value
                break
        if sessionid == None:
            print 'DEBUG: DAAPClient: login unable to determine session ID'
            return
        return DAAPSession(self, sessionid)
    def readResponse(self, data):
        objectlist  = []
        while len(data) > 0:
            object  = DAAPObject()
            data    = object.processData(data)
            objectlist.append(object)
            if data > 0:
                print 'DEBUG: readResponse: %s bytes of data left over' % len(data)
        return objectlist

class DAAPSession:
    def __init__(self, connection, sessionid):
        self.connection = connection
        self.sessionid  = sessionid
        self.revision   = 1
    def update(self):
        request     = '/update?session-id=%s' % self.sessionid
        print request
        self.connection.socket.request('GET', request, None, self.connection.headers)
        response    = self.connection.socket.getresponse()
        print response.status
        print response.msg
        if response.status == 403:
            print 'DEBUG: DAAPSession: update: forbidden'
        data        = response.read()
        response    = self.connection.readResponse(data)
        if len(response) != 1:
            print 'DEBUG: DAAPSession: update: wrong number of answers'
            return
        print response[0].printTree()
    def databases(self):
        request     = '/databases?session-id=%s&revision-number=%s' % (self.sessionid, self.revision)
        self.connection.socket.request('GET', request, None, self.connection.headers)
        response    = self.connection.socket.getresponse()
        if response.status == 403:
            print 'DEBUG: DAAPSession: databases: forbidden'
        data        = response.read()
        response    = self.connection.readResponse(data)
        if len(response) != 1:
            print 'DEBUG: DAAPSession: databases: wrong number of answers'
            return
        print response[0].printTree()
    def logout(self):
        self.connection.socket.request('GET', '/logout?session-id=%s' % self.sessionid, None, self.connection.headers)
        response    = self.connection.socket.getresponse()
        data        = response.read()
        response    = self.connection.readResponse(data)
        print 'DEBUG: DAAPSession: expired session id %s' % self.sessionid

if __name__ == '__main__':
    connection  = DAAPClient()
    connection.connect('arctic')
    connection.getContentCodes()
    connection.getInfo()
    #session        = connection.login()
    #print 'Session-ID: %s' % session.sessionid
    #if session == None:
    #   print '-- failed to get session -- abort --'
    #else:
    #   session.update()
    #   session.logout()
