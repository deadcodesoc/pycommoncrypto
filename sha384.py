#!/usr/bin/python

import sys
import _commoncrypto

digest2hex = lambda s: ''.join([hex(ord(x))[2:].zfill(2) for x in s])

def sha384(handler):
    ctx = _commoncrypto.SHA384_Init()
    while True:
        line = handler.readline(1024)
        if len(line) == 0: break
        _commoncrypto.SHA384_Update(ctx, line)
    s = _commoncrypto.SHA384_Final(ctx)
    return s

if __name__ == '__main__':
    if sys.argv[1:]:
        for arg in sys.argv[1:]:
            f = open(arg)
            s = sha384(f)
            print 'SHA384 (%s) = %s' % (arg, digest2hex(s))
            f.close()
    else:
        f = sys.stdin
        s = sha384(f)
        print digest2hex(s)
