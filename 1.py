'''
Aim: solve the Matasano Cryptopals challenges without using external libraries
'''

'''
'a' -> 10
'5' -> 5
'''
def hex_digit_to_dec(d):
    assert type(d) is str
    assert len(d) == 1
    d = d.lower()
    assert d in '0123456789abcdef'
    if d in '0123456789':
        return int(ord(d)-ord('0'))
    else:
        return 10+int(ord(d)-ord('a'))

'''
0 -> '0'
12 -> 'c'
'''
def dec_digit_to_hex(d, bounds_check=True):
    if bounds_check:
        assert type(d) is int
        assert 0 <= d < 16
    if d < 10:
        return chr(ord('0')+d)
    else:
        return chr(ord('a')+d-10)

'''
7 -> 'H'
60 -> '8'
38 -> 'm'
63 -> '/'
'''
def dec_digit_to_base64(d):
    assert type(d) is int
    assert 0 <= d < 64
    if d < 26:
        return chr(ord('A')+d)
    elif d < 52:
        return chr(ord('a')+d-26)
    elif d < 62:
        return chr(ord('0')+d-52)
    elif d == 62:
        return '+'
    else:
        return '/'

def hex_to_b64(s):
    i = len(s)-1
    res = []
    while i >= 2:
        a = hex_digit_to_dec(s[i-2])
        b = hex_digit_to_dec(s[i-1])
        c = hex_digit_to_dec(s[i])
        e = (a << 2) | ((b & 0b1100) >> 2)
        f = ((b & 0b11) << 4) | c
        res.append(dec_digit_to_base64(f))
        res.append(dec_digit_to_base64(e))
        i -= 3
    return ''.join(reversed(res))

# 1.1
temp = hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
assert temp == 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

###

def fixed_xor(buf1, buf2, bounds_check=True):
    assert type(buf1) is str
    assert type(buf2) is str
    assert len(buf1) == len(buf2)
    return ''.join(dec_digit_to_hex(hex_digit_to_dec(i) ^ hex_digit_to_dec(j), bounds_check) \
                   for i, j in zip(buf1, buf2))

# 1.2
assert fixed_xor('1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965') == '746865206b696420646f6e277420706c6179'

###

a = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

'''
Repeat an ASCII string so that the total length is n
'''
def repeat_ascii(s, n):
    assert type(n) is int
    assert n >= 0
    assert n % len(s) == 0
    return ''.join(s for _ in range(int(n/len(s))))

'''
Decode a hex string to an ASCII string
'36' -> '6' (because the ASCII value of the character '6' is 54 i.e. 0x36)
'''
def hex_decode(s):
    assert len(s) % 2 == 0
    return ''.join(chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2))

'''
Encode an ASCII string to hex
'6' -> '36'
'''
def hex_encode(s):
    return ''.join(hex(ord(c))[2:] for c in s)

assert hex_encode(hex_decode(a)) == a

f = open('enable1.txt')
WORDS = set(f.read().split())
f.close()
del f

'''
Score a string. Higher scores go to legible English text
1 point if it's in the legible ASCII range
2 points if it's a lowercase or uppercase letter
then another iteration checks for the presence of words that exist in enable1.txt
5 points for each dictionary word we find
'''
def score(s):
    global WORDS
    score = sum((' ' <= c <= '^' or 'a' <= c <= '~') + (c.lower() in 'abcdefghijklmnopqrstuvwxyz') for c in s)\
            + sum(5 * (w in WORDS) for w in s.split())
    return score

def break_single_byte_xor_cipher(s):
    assert len(s) % 2 == 0
    candidates = [hex_decode(fixed_xor(s, repeat_ascii(hex(i)[2:].rjust(2, '0'), len(s)))) for i in range(256)]
    return max(candidates, key=score)

# 1.3
print(break_single_byte_xor_cipher(a))

###

f = open('4.txt')
ciphertexts = f.read().split()
f.close()
del f

# 1.4
# This takes a while to run, so I commented it out
# plaintexts = [break_single_byte_xor_cipher(ciphertext) for ciphertext in ciphertexts]
# print(max(plaintexts, key=score))

###

def repeating_key_xor(s, k):
    assert type(s) == type(k) == str
    return ''.join([hex(ord(s[i])^ord(k[i%len(k)]))[2:].rjust(2,'0') for i in range(len(s))])

# 1.5
assert repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", 'ICE') == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

###

'''
Hamming distance between two equal-length ASCII strings
defined as the sum of the hamming distances for each pair of corresponding characters
'''
def hamming_ascii(s1, s2):
    assert type(s1) == type(s2) == str and len(s1) == len(s2)
    '''
    Count the number of bits that differ between the ord values of two chars
    '''
    def hamming_char(c1, c2):
        assert type(c1) == type(c2) == str and len(c1) == len(c2) == 1
        xor = ord(c1) ^ ord(c2)
        return sum((xor & (1 << i)) >> i for i in range(8))
    return sum(hamming_char(c1, c2) for c1, c2 in zip(s1, s2))

assert hamming_ascii('this is a test', 'wokka wokka!!!') == 37