block_size = 4096

def signature(f):
    while True:
        block_data = f.read(block_size)
        if not block_data:
            break
        yield (zlib.adler32(block_data), hashlib.md5(block_data).digest())

class RsyncLookupTable(object):

    def __init__(self, checksums):
        self.dict = {}
        for block_number, c in enumerate(checksums):
            weak, strong = c
            if weak not in self.dict:
                self.dict[weak] = dict()
            self.dict[weak][strong] = block_number

    def __getitem__(self, block_data):
        weak = zlib.adler32(block_data)
        subdict = self.dict.get(weak)
        if subdict:
            strong = hashlib.md5(block_data).digest()
            return subdict.get(strong)
        return None

def delta(sigs, f):
    table = RsyncLookupTable(sigs)
    block_data = f.read(block_size)
    while block_data:
        block_number = table[block_data]
        if block_number:
            yield (block_number * block_size, len(block_data))
            block_data = f.read(block_size)
        else:
            yield block_data[0]
            block_data = block_data[1:] + f.read(1)

def patch(outputf, deltas, old_file):
    for x in deltas:
        if type(x) == str:
            outputf.write(x)
        else:
            offset, length = x
            old_file.seek(offset)
            outputf.write(old_file.read(length))

