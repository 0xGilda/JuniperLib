import hashlib
import random
import re
import logging
import sys


logger = logging.getLogger(__name__)


ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
RND = None
MAGIC = "$9$"
FAMILY = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"]
EXTRA = {}
VALID = None
CHAR_REGEX = None
NUM_ALPHA = None
ALPHA_NUM = None
ENCODING = [ [1, 4, 32], [1, 16, 32], [1, 8, 32], [1, 64], [1, 32], [1, 4, 16, 128], [1, 32, 64] ]

RND = random.SystemRandom()

# Prepare EXTRA constant for use with encrypt9 method
for fam in range(0, len(FAMILY)):
    for c in FAMILY[fam]:
        EXTRA[c] = 3 - fam
        
# Prepare VALID and CHAR_REGEX Regex pattern constants for use with decrypt9 method
letters = ""
for item in FAMILY:
    letters += item
end = "[" + letters + "]{4,}$"
end = end.replace("-", "\\-")
VALID = re.compile("^" + str.replace(MAGIC, "$", "\$") + end)
CHAR_REGEX = re.compile("^" + str.replace(MAGIC, "$", "\$") + "(\\S+)")

# Prepare NUM_ALPHA and ALPHA_NUM constants for use with encrypt9 method
NUM_ALPHA = []
for char in letters:
    NUM_ALPHA.append(char)
ALPHA_NUM = {}
for num in range(0, len(NUM_ALPHA)):
    ALPHA_NUM[NUM_ALPHA[num]] = num
        

def encrypt1(pw):
    '''
        Create a non-reversable $1 password used for user logins on Junos configurations.  Wrapper with try block and random salt creations for the crypt method.
    '''
    try:
        return _crypt(pw, randomSalt(8))
    except:
        return None
    

def encrypt9(pw):
    '''
        Creates a reversable $9 password used for most passwords in Junos configuration.
    '''
    salt = randomSalt(1)
    rand = randomSalt(EXTRA[salt])
    pos = 0
    prev = salt
    crypt = MAGIC + salt + rand
    
    for char in pw:
        encode = ENCODING[pos % len(ENCODING)]
        crypt += _gapEncode(char, prev, encode)
        prev = crypt[len(crypt) - 1:]
        pos += 1
        
    return crypt


def decrypt9(crypt):
    '''
        Creates a plain text password from a $9 password that is used for most passwords in Junos configurations.
    '''
    # If not a valid $9 password then return None
    if crypt == None or crypt == "" or not VALID.match(crypt):
        logger.error("Decryption failed: Invalid $9 encryption string (" + str(crypt) + ")")
        return None
    
    charMatcher = CHAR_REGEX.match(crypt)
    chars = [charMatcher.group(1)]
    
    # Grab salt and clear it off
    first = _nibble(chars, 1)
    _nibble(chars, EXTRA[first])
    
    # Exit method if first is empty as error occurred
    if not first:
        logger.error("Decryption failed: Unable to find salt in encryption string (" + str(crypt) + ")")
        return None
    
    prev = first
    decrypt = ""
    
    while chars[0]:
        decode = ENCODING[len(decrypt) % len(ENCODING)]
        length = len(decode)
        
        # Split crypt in to gap values for decode
        nibble = _nibble(chars, length)
        gaps = []
        for item in nibble:
            g = _gap(prev, item)
            prev = item
            gaps.append(g)
            
        # Generate the plaintext character
        decodeChar = _gapDecode(gaps, decode)
        if not decodeChar:
            logger.error("Decryption failed: Unable to generate plaintext character at gaps: " + str(gaps) + " using decode: " + str(decode))
            return None
        decrypt += decodeChar
        
    return decrypt
            


def randomSalt(length):
    result = ""
    for i in range(0, length):
        result += ITOA64[RND.randint(0,len(ITOA64) - 1)]
    return result


def _crypt(pw, salt):
    pass


def _gap(c1, c2):
    firstOp = ALPHA_NUM[c2] - ALPHA_NUM[c1]
    while firstOp < 0:
        firstOp += len(NUM_ALPHA)
        
    return firstOp % len(NUM_ALPHA) - 1
    

def _gapDecode(gaps, dec):
    num = 0
    
    if len(gaps) != len(dec):
        logger.error("GapDecode found nibble and decode sizes are not the same!")
        return None

    for x in range(0, len(gaps)):
        num += gaps[x] * dec[x]
        
    return chr(num % 256)


def _gapEncode(pc, prev, enc):
    crypt = ""
    ordValue = ord(pc)
    gaps = []
    
    for x in range(len(enc) - 1, -1, -1):
        gaps.insert(0, ordValue / enc[x])
        ordValue %= enc[x]
        
    for item in gaps:
        item += ALPHA_NUM[prev] + 1
        c = prev = NUM_ALPHA[item % len(NUM_ALPHA)]
        crypt += c
        
    return crypt


def _nibble(cref, length):
    try:
        nib = cref[0][:length]
        cref[0] = cref[0][length:]
        
        return nib
    except IndexError:
        logger.error("Nibble ran out of characters: hit " + str(cref) + ", expecting " + str(length) + " characters.")
        return None


def _to64(v, n):
    pass
