import volatility.plugins.common as common
import volatility.scan as scan
import volatility.utils as utils
import volatility.addrspace as addrspace
import volatility.debug as debug
import volatility.obj as obj
import binascii

FORWARD = 1
BACKWARD = -1

def find_varint(buff, start, direct):
    """ varint are 1-9 bytes, big-endian.  The most sig bit is not used, which is why 128 is subtracted
    in the for loops below."""
    buff_len = len(buff)
    varint_len = 1
    varint_buff = ""
    begin = 0
    # at start index and going backwards, so only 1 byte available
    if direct == BACKWARD and start == 0:
        begin = 0
    # going backwards
    elif direct == BACKWARD:
        # set stopping point, lowest possible is start of the buffer
        if start >= 9:
            stop = start - 9
        else:
            stop = 0
        for i in range(start, stop, direct):
            if ord(buff[i-1]) < 128:
                break
            if i > stop + 1:
                varint_len += 1
        begin = start - varint_len + 1
    # going forwards
    else:
        # set a stopping point, maximum length of 9 bytes
        if start + 9 > buff_len:
            stop = buff_len
        else:
            stop = start + 9
        begin = start
        for i in range(start, stop, direct):
            if ord(buff[i]) < 128:
                break
            if i < stop-1:
                varint_len += 1
    # num_buff contains the varint that was extracted
    num_buff = buff[begin:begin+varint_len]

    if num_buff == "":
        return (-1, 0)
    return (varint_to_int(num_buff), varint_len)

def varint_to_text_length(l):
    """ Text field lengths are doubled and 13 is added so that they are odd and at least 13 """
    if l == 0:
        return 0
    else:
        return (l - 13) / 2

def varint_to_int(buff):
    """ convert a varint to an integer """

    bin_str = ""
    varint_len = len(buff)
    # convert each byte to a binary string, keeping 7 bytes, unless the buffer is 9 bytes and
    # and we are grabbing the last byte, then keep all 8
    for i in range(0,varint_len):
        if i == 8 and varint_len == 9:
            bin_str += bin(ord(buff[i]))[2:].zfill(8)
        else:
            bin_str += bin(ord(buff[i]))[2:].zfill(8)[1:]

    if len(bin_str) == 64 and bin_str[0] == '1':
        # negative numbers use all 64 bits and will start with a 1.
        # take the ones complement, add 1, then put a negative sign in front
        sub_bin_str = ones_comp(bin_str)
        value = -(int(sub_bin_str, 2) + 1)
    else:
        value = int(bin_str, 2)

    return value

class FirefoxScanner(scan.BaseScanner):
    checks = [ ] 

    def __init__(self, needles = None):
        self.needles = needles
        self.checks = [ ("MultiStringFinderCheck", {'needles':needles})]
        scan.BaseScanner.__init__(self) 

    def scan(self, address_space, offset = 0, maxlen = None):
        for offset in scan.BaseScanner.scan(self, address_space, offset, maxlen):
            yield offset

class FireFoxHistory(common.AbstractWindowsCommand):
    """ Scans for and parses potential Firefox url history (places.sqlite moz_places table)"""

    def __init__(self, config, *args, **kwargs):
        common.AbstractWindowsCommand.__init__(self, config, *args, **kwargs)
        
    def calculate(self):
        address_space = utils.load_as(self._config, astype = 'physical')

        # definite values in History records
        scanner = FirefoxScanner(needles = ['\x06\x25',
                                            '\x00\x25',
                                           ])
        urls = {}
        for offset in scanner.scan(address_space):
            ff_buff = address_space.read(offset-21, 3000)
            start = 21
            # new field foreign_count added around Firefox v34
            foreign_count_length = 0
            foreign_count = "N/A"

            # start before the needle match and work backwards
            if ord(ff_buff[start-1]) in (1, 2, 8, 9):
                start -= 1
            else:
                continue

            if ord(ff_buff[start-1]) in (0, 1, 8, 9):
                start -= 1
            else:
                continue

            if ord(ff_buff[start-1]) not in (8, 9):
                continue
            start -= 1

            if ord(ff_buff[start-1]) not in (8, 9):
                continue
            start -= 1

            if ord(ff_buff[start-1]) in (1, 8, 9):
                start -= 1
            else:
                continue

            start -= 1
            (temp, varint_len) = find_varint(ff_buff, start, BACKWARD)

            start -= varint_len
            (temp, varint_len) = find_varint(ff_buff, start, BACKWARD)
           
            start -= varint_len
            (url_length, varint_len) = find_varint(ff_buff, start, BACKWARD)
            url_length = varint_to_text_length(url_length)
            
            start -= varint_len
            url_id_length = ord(ff_buff[start])

            start -= 1
            payload_header_end = start + ord(ff_buff[start])

            start -= 1
            (row_id, varint_len) = find_varint(ff_buff, start, BACKWARD)
            # can't have a negative row_id (index)
            if row_id < 0:
                continue

            start -= varint_len
            if start < 0:
                continue
            (payload_length, varint_len) = find_varint(ff_buff, start, BACKWARD)

            # payload_length should be much longer than this, but this is a safe minimum
            if payload_length < 6:
                continue

            # go back to the needle match and start processing forward
            (temp, varint_len) = find_varint(ff_buff, 22, FORWARD)
            start = 22 + varint_len

            # Firefox added a "foreign_count" field that needs to be handled
            if start != payload_header_end:
                start += 1

            start += url_id_length
            url = ff_buff[start:start+url_length].strip()
            if url[0:4] == "http":
                yield url
            
    def render_text(self, outfd, data):
        self.table_header(outfd, [("URL", "80")])
        for url in data:
            self.table_row(outfd, url)
