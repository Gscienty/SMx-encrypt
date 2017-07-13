from functools import reduce
def sm3hash(message):
    iv = list(b'\x73\x80\x16\x6f\x49\x14\xb2\xb9\x17\x24\x42\xd7\xda\x8a\x06\x00\xa9\x6f\x30\xbc\x16\x31\x38\xaa\xe3\x8d\xee\x4d\xb0\xfb\x0e\x4e')
    t = lambda j: list(b'\x79\xcc\x45\x19') if 0 <= j and j <= 15 else list(b'\x7a\x87\x9d\x8a')
    ff = lambda j, wx, wy, wz: bytes ( list ( map ( lambda x, y, z: x ^ y ^ z, wx, wy, wz ) ) ) if 0 <= j and j <= 15 else bytes( list( map( lambda x, y, z: ( x & y ) | ( x & z ) | ( y & z ), wx, wy, wz ) ) )
    gg = lambda j, wx, wy, wz: bytes( list( map ( lambda x, y, z: x ^ y ^ z, wx, wy, wz ) ) ) if 0 <= j <= 15 else bytes( list ( map ( lambda x, y, z: ( x & y ) | ( ( ~x ) & z ), wx, wy, wz ) ) )
    leftcur = lambda c, w: bytes ( list( w ) ) if c == 0 else leftcur( c - 1, [ ( ( w[i] << 1 ) | ( ( w[( lambda x: x + 1 if x != 3 else 0 ) ( i )] & 0x80 ) >> 7 ) ) % 0x100 for i in range(0, 4) ] )
    int2buff = lambda x: [ x ] if x // 256 == 0 else int2buff( ( x & 0xffffffffffffff00 ) >> 8 ) + [ ( x & 0x00000000000000ff ) ]
    extendbuff = lambda l, x: x if x == l else [ 0x00 for i in range( 0, l - len(x) ) ] + x
    add = lambda wx, wy: wx if len( list( filter( lambda x: x != 0, wy ) ) ) == 0 else add( (lambda wx, wy: [ (wx[i] + wy[i]) % 256 for i in range(0, 4) ])(wx, wy), (lambda wx, wy: [ 0 if i == 3 else ( wx[i + 1] + wy[i + 1] ) // 256 for i in range(0, 4) ])(wx, wy) )
    xor = lambda wx, wy: [ wx[i] ^ wy[i] for i in range(0, 4) ]
    p = lambda m, w: xor( xor( w, leftcur( 9, w ) ), leftcur(17, w) ) if m == 0 else xor( xor( w, leftcur( 15, w ) ), leftcur(23, w) )
    def cf(v, m):
        w = [ m[i * 4: (i + 1) * 4] for i in range( 0, 16 ) ]
        for j in range(16, 68): w.append( xor( xor( p( 1, xor( xor( w[ j - 16 ], w[ j - 9 ] ), leftcur( 15, w[ j - 3 ] ) ) ), leftcur( 7, w[ j - 13 ] ) ), w[ j - 6 ] ) )
        wc = [ xor( w[ j ], w[ j + 4 ] ) for j in range(0, 64) ]
        r = [ v[ 0: 4 ], v[ 4: 8 ], v[ 8: 12 ], v[ 12: 16 ], v[ 16: 20 ], v[ 20: 24 ], v[ 24: 28 ], v[ 28: 32 ] ]
        for j in range(0, 64):
            ss1 = leftcur( 7, add( add( leftcur(12, r[0]), r[4] ), leftcur( j, t( j ) ) ) ) 
            ss2 = xor( ss1, leftcur( 12, r[0] ) )
            tt1 = add( add( add( ff( j, r[0], r[1], r[2] ), r[3] ), ss2 ), wc[ j ] )
            tt2 = add( add( add( gg( j, r[4], r[5], r[6] ), r[7] ), ss1 ), w[ j ] )
            r[3] = r[2]
            r[2] = leftcur( 9, r[1] )
            r[1] = r[0]
            r[0] = tt1
            r[7] = r[6]
            r[6] = leftcur( 19, r[5] )
            r[5] = r[4]
            r[4] = p( 0, tt2 )
        vnext = map(lambda wx, wy: xor(wx, wy), r,  [ v[ 0: 4 ], v[ 4: 8 ], v[ 8: 12 ], v[ 12: 16 ], v[ 16: 20 ], v[ 20: 24 ], v[ 24: 28 ], v[ 28: 32 ] ] )
        return list(reduce(lambda x, a: x + a, vnext, []))
    bag = list( message )
    bit_len = len(bag) * 8
    bag = bag + [ 0x80 ] + [ 0x00 for i in range((448 - ( bit_len % 512 )) // 8 - 1) ] + extendbuff( 8, int2buff( bit_len ) )
    for i in range(0, len( bag ) // 64): iv = cf( iv, bag[ i * 64: (i + 1) * 64 ] )
    return iv
