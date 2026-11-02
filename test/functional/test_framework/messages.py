#!/usr/bin/env python3
# Copyright (c) 2010 ArtForz -- public domain half-a-node
# Copyright (c) 2012 Jeff Garzik
# Copyright (c) 2010-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Bitcoin test framework primitive and message structures

CBlock, CTransaction, CBlockHeader, CTxIn, CTxOut, etc....:
    data structures that should map to corresponding structures in
    bitcoin/primitives

msg_block, msg_tx, msg_headers, etc.:
    data structures that represent network messages

ser_*, deser_*: functions that handle serialization/deserialization.

Classes use __slots__ to ensure extraneous attributes aren't accidentally added
by tests, compromising their intended effect.
"""
from base64 import b32decode, b32encode
import copy
import hashlib
from io import BytesIO
import math
import random
import socket
import struct
import time
import unittest

try:
    import blake3 as BLAKE3  # type: ignore[import-not-found]
except ImportError:
    from test_framework.crypto import blake3 as BLAKE3
from test_framework.crypto.kheavyhash import kheavyhash
from test_framework.crypto.siphash import siphash256
from test_framework.util import (
    assert_equal,
    assert_not_equal,
)

MAX_LOCATOR_SZ = 101
MAX_BLOCK_WEIGHT = 4000000
MAX_BLOCK_SIGOPS_COST = 80000
DEFAULT_BLOCK_RESERVED_WEIGHT = 8000
MINIMUM_BLOCK_RESERVED_WEIGHT = 2000
MAX_BLOOM_FILTER_SIZE = 36000
MAX_BLOOM_HASH_FUNCS = 50

COIN = 100000000  # 1 zork in satoshis
MAX_MONEY = 9007199253692420  # 0x001FFFFF_FFF00004 sat; matches src/consensus/amount.h

MAX_BIP125_RBF_SEQUENCE = 0xfffffffd  # Sequence number that is rbf-opt-in (BIP 125) and csv-opt-out (BIP 68)
MAX_SEQUENCE_NONFINAL = 0xfffffffe  # Sequence number that is csv-opt-out (BIP 68)
SEQUENCE_FINAL = 0xffffffff  # Sequence number that disables nLockTime if set for every input of a tx

MAX_PROTOCOL_MESSAGE_LENGTH = 32 * 1000 * 1000  # Maximum length of incoming protocol messages (Litecoin/MWEB)
MAX_HEADERS_RESULTS = 2000  # Number of headers sent in one getheaders result
MAX_INV_SIZE = 50000  # Maximum number of entries in an 'inv' protocol message

NODE_NONE = 0
NODE_NETWORK = (1 << 0)
NODE_BLOOM = (1 << 2)
NODE_WITNESS = (1 << 3)
NODE_COMPACT_FILTERS = (1 << 6)
NODE_NETWORK_LIMITED = (1 << 10)
NODE_P2P_V2 = (1 << 11)
NODE_MWEB_LIGHT_CLIENT = (1 << 23)
NODE_MWEB = (1 << 24)

MSG_TX = 1
MSG_BLOCK = 2
MSG_FILTERED_BLOCK = 3
MSG_CMPCT_BLOCK = 4
MSG_WTX = 5
MSG_WITNESS_FLAG = 1 << 30
MSG_MWEB_FLAG = 1 << 29
MSG_TYPE_MASK = 0xffffffff >> 3
MSG_WITNESS_TX = MSG_TX | MSG_WITNESS_FLAG
MSG_MWEB_BLOCK = MSG_BLOCK | MSG_WITNESS_FLAG | MSG_MWEB_FLAG
MSG_MWEB_TX = MSG_WITNESS_TX | MSG_MWEB_FLAG
MSG_MWEB_HEADER = 8 | MSG_MWEB_FLAG
MSG_MWEB_LEAFSET = 9 | MSG_MWEB_FLAG

MWEB_UTXO_FORMAT_FULL = 0
MWEB_UTXO_FORMAT_HASH_ONLY = 1
MWEB_UTXO_FORMAT_COMPACT = 2

FILTER_TYPE_BASIC = 0

WITNESS_SCALE_FACTOR = 4

DEFAULT_ANCESTOR_LIMIT = 25    # default max number of in-mempool ancestors
DEFAULT_DESCENDANT_LIMIT = 25  # default max number of in-mempool descendants
DEFAULT_CLUSTER_LIMIT = 64     # default max number of transactions in a cluster


# Default setting for -datacarriersize.
MAX_OP_RETURN_RELAY = 100_000


DEFAULT_MEMPOOL_EXPIRY_HOURS = 336  # hours

TX_MIN_STANDARD_VERSION = 1
TX_MAX_STANDARD_VERSION = 3

MAGIC_BYTES = {
    "mainnet": b"\xf7\x1d\xdc\x3d",
    "testnet3": b"\xf7\x2d\xdc\x3d",
    "testnet4": b"\xf7\x3d\xdc\x3d",
    "regtest": b"\xf7\x4d\xdc\x3d",
    "signet": b"\x54\xd2\x6f\xbd",
}

def sha256(s):
    return hashlib.sha256(s).digest()


def sha3(s):
    return hashlib.sha3_256(s).digest()


def hash256(s):
    return sha256(sha256(s))


def ser_compact_size(l):
    r = b""
    if l < 253:
        r = l.to_bytes(1, "little")
    elif l < 0x10000:
        r = (253).to_bytes(1, "little") + l.to_bytes(2, "little")
    elif l < 0x100000000:
        r = (254).to_bytes(1, "little") + l.to_bytes(4, "little")
    else:
        r = (255).to_bytes(1, "little") + l.to_bytes(8, "little")
    return r


def deser_compact_size(f):
    nit = int.from_bytes(f.read(1), "little")
    if nit == 253:
        nit = int.from_bytes(f.read(2), "little")
    elif nit == 254:
        nit = int.from_bytes(f.read(4), "little")
    elif nit == 255:
        nit = int.from_bytes(f.read(8), "little")
    return nit


def ser_varint(l):
    r = b""
    while True:
        r = bytes([(l & 0x7f) | (0x80 if len(r) > 0 else 0x00)]) + r
        if l <= 0x7f:
            return r
        l = (l >> 7) - 1


def deser_varint(f):
    n = 0
    while True:
        dat = f.read(1)[0]
        n = (n << 7) | (dat & 0x7f)
        if (dat & 0x80) > 0:
            n += 1
        else:
            return n


def deser_string(f):
    nit = deser_compact_size(f)
    return f.read(nit)


def ser_string(s):
    return ser_compact_size(len(s)) + s


def deser_uint256(f):
    return int.from_bytes(f.read(32), 'little')


def ser_uint256(u):
    return u.to_bytes(32, 'little')


def uint256_from_str(s):
    return int.from_bytes(s[:32], 'little')


def uint256_from_compact(c):
    nbytes = (c >> 24) & 0xFF
    v = (c & 0xFFFFFF) << (8 * (nbytes - 3))
    return v


def deser_fixed_bytes(f, size):
    r = []
    for i in range(size):
        r.append(struct.unpack("B", f.read(1))[0])
    return r

def ser_fixed_bytes(u, size):
    rs = b""
    for i in range(size):
        rs += struct.pack("B", u[i])
        #rs += struct.pack("B", u & 0xFF)
        #u >>= 8
    return rs


def deser_pubkey(f):
    r = 0
    for i in range(33):
        t = struct.unpack("B", f.read(1))[0]
        r += t << (i * 8)
    return r

def ser_pubkey(u):
    rs = b""
    for _ in range(33):
        rs += struct.pack("B", u & 0xFF)
        u >>= 8
    return rs


def deser_signature(f):
    r = 0
    for i in range(64):
        t = struct.unpack("B", f.read(1))[0]
        r += t << (i * 8)
    return r

def ser_signature(u):
    rs = b""
    for _ in range(64):
        rs += struct.pack("B", u & 0xFF)
        u >>= 8
    return rs



# deser_function_name: Allow for an alternate deserialization function on the
# entries in the vector.
def deser_vector(f, c, deser_function_name=None):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = c()
        if deser_function_name:
            getattr(t, deser_function_name)(f)
        else:
            t.deserialize(f)
        r.append(t)
    return r


# ser_function_name: Allow for an alternate serialization function on the
# entries in the vector (we use this for serializing the vector of transactions
# for a witness block).
def ser_vector(l, ser_function_name=None):
    r = ser_compact_size(len(l))
    for i in l:
        if ser_function_name:
            r += getattr(i, ser_function_name)()
        else:
            r += i.serialize()
    return r


def deser_uint256_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_uint256(f)
        r.append(t)
    return r


def ser_uint256_vector(l):
    r = ser_compact_size(len(l))
    for i in l:
        r += ser_uint256(i)
    return r


def deser_string_vector(f):
    nit = deser_compact_size(f)
    r = []
    for _ in range(nit):
        t = deser_string(f)
        r.append(t)
    return r


def ser_string_vector(l):
    r = ser_compact_size(len(l))
    for sv in l:
        r += ser_string(sv)
    return r


def deser_block_spent_outputs(f):
    nit = deser_compact_size(f)
    return [deser_vector(f, CTxOut) for _ in range(nit)]


def from_hex(obj, hex_string):
    """Deserialize from a hex string representation (e.g. from RPC)

    Note that there is no complementary helper like e.g. `to_hex` for the
    inverse operation. To serialize a message object to a hex string, simply
    use obj.serialize().hex()"""
    obj.deserialize(BytesIO(bytes.fromhex(hex_string)))
    return obj


FromHex = from_hex


def tx_from_hex(hex_string):
    """Deserialize from hex string to a transaction object"""
    return from_hex(CTransaction(), hex_string)


def malleate_tx_to_invalid_witness(tx):
    """
    Create a malleated version of the tx where the witness is replaced with garbage data.
    Returns a CTransaction object.
    """
    tx_bad_wit = tx_from_hex(tx["hex"])
    tx_bad_wit.wit.vtxinwit = [CTxInWitness()]
    # Add garbage data to witness 0. We cannot simply strip the witness, as the node would
    # classify it as a transaction in which the witness was missing rather than wrong.
    tx_bad_wit.wit.vtxinwit[0].scriptWitness.stack = [b'garbage']

    assert_equal(tx["txid"], tx_bad_wit.txid_hex)
    assert_not_equal(tx["wtxid"], tx_bad_wit.wtxid_hex)

    return tx_bad_wit


# like from_hex, but without the hex part
def from_binary(cls, stream):
    """deserialize a binary stream (or bytes object) into an object"""
    # handle bytes object by turning it into a stream
    was_bytes = isinstance(stream, bytes)
    if was_bytes:
        stream = BytesIO(stream)
    obj = cls()
    obj.deserialize(stream)
    if was_bytes:
        assert_equal(len(stream.read()), 0)
    return obj


# Objects that map to bitcoind objects, which can be serialized/deserialized


class CAddress:
    __slots__ = ("net", "ip", "nServices", "port", "time")

    # see https://github.com/bitcoin/bips/blob/master/bip-0155.mediawiki
    NET_IPV4 = 1
    NET_IPV6 = 2
    NET_TORV3 = 4
    NET_I2P = 5
    NET_CJDNS = 6

    ADDRV2_NET_NAME = {
        NET_IPV4: "IPv4",
        NET_IPV6: "IPv6",
        NET_TORV3: "TorV3",
        NET_I2P: "I2P",
        NET_CJDNS: "CJDNS"
    }

    ADDRV2_ADDRESS_LENGTH = {
        NET_IPV4: 4,
        NET_IPV6: 16,
        NET_TORV3: 32,
        NET_I2P: 32,
        NET_CJDNS: 16
    }

    I2P_PAD = "===="

    def __init__(self):
        self.time = 0
        self.nServices = 1
        self.net = self.NET_IPV4
        self.ip = "0.0.0.0"
        self.port = 0

    def __eq__(self, other):
        return self.net == other.net and self.ip == other.ip and self.nServices == other.nServices and self.port == other.port and self.time == other.time

    def deserialize(self, f, *, with_time=True):
        """Deserialize from addrv1 format (pre-BIP155)"""
        if with_time:
            # VERSION messages serialize CAddress objects without time
            self.time = int.from_bytes(f.read(4), "little")
        self.nServices = int.from_bytes(f.read(8), "little")
        # We only support IPv4 which means skip 12 bytes and read the next 4 as IPv4 address.
        f.read(12)
        self.net = self.NET_IPV4
        self.ip = socket.inet_ntoa(f.read(4))
        self.port = int.from_bytes(f.read(2), "big")

    def serialize(self, *, with_time=True):
        """Serialize in addrv1 format (pre-BIP155)"""
        assert_equal(self.net, self.NET_IPV4)
        r = b""
        if with_time:
            # VERSION messages serialize CAddress objects without time
            r += self.time.to_bytes(4, "little")
        r += self.nServices.to_bytes(8, "little")
        r += b"\x00" * 10 + b"\xff" * 2
        r += socket.inet_aton(self.ip)
        r += self.port.to_bytes(2, "big")
        return r

    def deserialize_v2(self, f):
        """Deserialize from addrv2 format (BIP155)"""
        self.time = int.from_bytes(f.read(4), "little")

        self.nServices = deser_compact_size(f)

        self.net = int.from_bytes(f.read(1), "little")
        assert self.net in self.ADDRV2_NET_NAME

        address_length = deser_compact_size(f)
        assert_equal(address_length, self.ADDRV2_ADDRESS_LENGTH[self.net])

        addr_bytes = f.read(address_length)
        if self.net == self.NET_IPV4:
            self.ip = socket.inet_ntoa(addr_bytes)
        elif self.net == self.NET_IPV6:
            self.ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        elif self.net == self.NET_TORV3:
            prefix = b".onion checksum"
            version = bytes([3])
            checksum = sha3(prefix + addr_bytes + version)[:2]
            self.ip = b32encode(addr_bytes + checksum + version).decode("ascii").lower() + ".onion"
        elif self.net == self.NET_I2P:
            self.ip = b32encode(addr_bytes)[0:-len(self.I2P_PAD)].decode("ascii").lower() + ".b32.i2p"
        elif self.net == self.NET_CJDNS:
            self.ip = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        else:
            raise Exception("Address type not supported")

        self.port = int.from_bytes(f.read(2), "big")

    def serialize_v2(self):
        """Serialize in addrv2 format (BIP155)"""
        assert self.net in self.ADDRV2_NET_NAME
        r = b""
        r += self.time.to_bytes(4, "little")
        r += ser_compact_size(self.nServices)
        r += self.net.to_bytes(1, "little")
        r += ser_compact_size(self.ADDRV2_ADDRESS_LENGTH[self.net])
        if self.net == self.NET_IPV4:
            r += socket.inet_aton(self.ip)
        elif self.net == self.NET_IPV6:
            r += socket.inet_pton(socket.AF_INET6, self.ip)
        elif self.net == self.NET_TORV3:
            sfx = ".onion"
            assert self.ip.endswith(sfx)
            r += b32decode(self.ip[0:-len(sfx)], True)[0:32]
        elif self.net == self.NET_I2P:
            sfx = ".b32.i2p"
            assert self.ip.endswith(sfx)
            r += b32decode(self.ip[0:-len(sfx)] + self.I2P_PAD, True)
        elif self.net == self.NET_CJDNS:
            r += socket.inet_pton(socket.AF_INET6, self.ip)
        else:
            raise Exception("Address type not supported")
        r += self.port.to_bytes(2, "big")
        return r

    def __repr__(self):
        return ("CAddress(nServices=%i net=%s addr=%s port=%i)"
                % (self.nServices, self.ADDRV2_NET_NAME[self.net], self.ip, self.port))


class CInv:
    __slots__ = ("hash", "type")

    typemap = {
        0: "Error",
        MSG_TX: "TX",
        MSG_BLOCK: "Block",
        MSG_TX | MSG_WITNESS_FLAG: "WitnessTx",
        MSG_BLOCK | MSG_WITNESS_FLAG: "WitnessBlock",
        MSG_FILTERED_BLOCK: "filtered Block",
        MSG_CMPCT_BLOCK: "CompactBlock",
        MSG_WTX: "WTX",
        MSG_TX | MSG_WITNESS_FLAG | MSG_MWEB_FLAG: "MWEB Tx",
        MSG_BLOCK | MSG_WITNESS_FLAG | MSG_MWEB_FLAG: "MWEB Block",
        MSG_MWEB_HEADER: "MWEB Header",
        MSG_MWEB_LEAFSET: "MWEB Leafset",
    }

    def __init__(self, t=0, h=0):
        self.type = t
        self.hash = h

    def deserialize(self, f):
        self.type = int.from_bytes(f.read(4), "little")
        self.hash = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.type.to_bytes(4, "little")
        r += ser_uint256(self.hash)
        return r

    def __repr__(self):
        return "CInv(type=%s hash=%064x)" \
            % (self.typemap[self.type], self.hash)

    def __eq__(self, other):
        return isinstance(other, CInv) and self.hash == other.hash and self.type == other.type


class CBlockLocator:
    __slots__ = ("nVersion", "vHave")

    def __init__(self):
        self.vHave = []

    def deserialize(self, f):
        int.from_bytes(f.read(4), "little", signed=True)  # Ignore version field.
        self.vHave = deser_uint256_vector(f)

    def serialize(self):
        r = b""
        r += (0).to_bytes(4, "little", signed=True)  # Bitcoin Core ignores the version field. Set it to 0.
        r += ser_uint256_vector(self.vHave)
        return r

    def __repr__(self):
        return "CBlockLocator(vHave=%s)" % (repr(self.vHave))


class COutPoint:
    __slots__ = ("hash", "n")

    def __init__(self, hash=0, n=0):
        self.hash = hash
        self.n = n

    def deserialize(self, f):
        self.hash = deser_uint256(f)
        self.n = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += ser_uint256(self.hash)
        r += self.n.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "COutPoint(hash=%064x n=%i)" % (self.hash, self.n)


class CTxIn:
    __slots__ = ("nSequence", "prevout", "scriptSig")

    def __init__(self, outpoint=None, scriptSig=b"", nSequence=0):
        if outpoint is None:
            self.prevout = COutPoint()
        else:
            self.prevout = outpoint
        self.scriptSig = scriptSig
        self.nSequence = nSequence

    def deserialize(self, f):
        self.prevout = COutPoint()
        self.prevout.deserialize(f)
        self.scriptSig = deser_string(f)
        self.nSequence = int.from_bytes(f.read(4), "little")

    def serialize(self):
        r = b""
        r += self.prevout.serialize()
        r += ser_string(self.scriptSig)
        r += self.nSequence.to_bytes(4, "little")
        return r

    def __repr__(self):
        return "CTxIn(prevout=%s scriptSig=%s nSequence=%i)" \
            % (repr(self.prevout), self.scriptSig.hex(),
               self.nSequence)


class CTxOut:
    __slots__ = ("nValue", "scriptPubKey")

    def __init__(self, nValue=0, scriptPubKey=b""):
        self.nValue = nValue
        self.scriptPubKey = scriptPubKey

    def deserialize(self, f):
        self.nValue = int.from_bytes(f.read(8), "little", signed=True)
        self.scriptPubKey = deser_string(f)

    def serialize(self):
        r = b""
        r += self.nValue.to_bytes(8, "little", signed=True)
        r += ser_string(self.scriptPubKey)
        return r

    def __repr__(self):
        return "CTxOut(nValue=%i.%08i scriptPubKey=%s)" \
            % (self.nValue // COIN, self.nValue % COIN,
               self.scriptPubKey.hex())


class CScriptWitness:
    __slots__ = ("stack",)

    def __init__(self):
        # stack is a vector of strings
        self.stack = []

    def __repr__(self):
        return "CScriptWitness(%s)" % \
               (",".join([x.hex() for x in self.stack]))

    def is_null(self):
        if self.stack:
            return False
        return True


class CTxInWitness:
    __slots__ = ("scriptWitness",)

    def __init__(self):
        self.scriptWitness = CScriptWitness()

    def deserialize(self, f):
        self.scriptWitness.stack = deser_string_vector(f)

    def serialize(self):
        return ser_string_vector(self.scriptWitness.stack)

    def __repr__(self):
        return repr(self.scriptWitness)

    def is_null(self):
        return self.scriptWitness.is_null()


class CTxWitness:
    __slots__ = ("vtxinwit",)

    def __init__(self):
        self.vtxinwit = []

    def deserialize(self, f):
        for i in range(len(self.vtxinwit)):
            self.vtxinwit[i].deserialize(f)

    def serialize(self):
        r = b""
        # This is different than the usual vector serialization --
        # we omit the length of the vector, which is required to be
        # the same length as the transaction's vin vector.
        for x in self.vtxinwit:
            r += x.serialize()
        return r

    def __repr__(self):
        return "CTxWitness(%s)" % \
               (';'.join([repr(x) for x in self.vtxinwit]))

    def is_null(self):
        for x in self.vtxinwit:
            if not x.is_null():
                return False
        return True


class CTransaction:
    __slots__ = ("nLockTime", "version", "vin", "vout", "wit", "mweb_tx", "hogex")

    def __init__(self, tx=None):
        if tx is None:
            self.version = 2
            self.vin = []
            self.vout = []
            self.wit = CTxWitness()
            self.nLockTime = 0
            self.mweb_tx = None
            self.hogex = False
        else:
            self.version = tx.version
            self.vin = copy.deepcopy(tx.vin)
            self.vout = copy.deepcopy(tx.vout)
            self.nLockTime = tx.nLockTime
            self.wit = copy.deepcopy(tx.wit)
            self.mweb_tx = tx.mweb_tx
            self.hogex = tx.hogex

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.vin = deser_vector(f, CTxIn)
        flags = 0
        if len(self.vin) == 0:
            flags = int.from_bytes(f.read(1), "little")
            # Not sure why flags can't be zero, but this
            # matches the implementation in bitcoind
            if (flags != 0):
                self.vin = deser_vector(f, CTxIn)
                self.vout = deser_vector(f, CTxOut)
        else:
            self.vout = deser_vector(f, CTxOut)
        if flags & 1:
            self.wit.vtxinwit = [CTxInWitness() for _ in range(len(self.vin))]
            self.wit.deserialize(f)
        else:
            self.wit = CTxWitness()

        if flags & 8:
            self.mweb_tx = deser_mweb_tx(f)
            if self.mweb_tx is None:
                self.hogex = True
        else:
            self.mweb_tx = None
            self.hogex = False

        self.nLockTime = int.from_bytes(f.read(4), "little")

    def serialize_without_witness(self):
        r = b""
        r += self.version.to_bytes(4, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Only serialize with witness when explicitly called for
    def serialize_with_witness(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        r = b""
        r += self.version.to_bytes(4, "little")
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += flags.to_bytes(1, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                # vtxinwit must have the same length as vin
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        r += self.nLockTime.to_bytes(4, "little")
        return r

    def serialize_with_mweb(self):
        flags = 0
        if not self.wit.is_null():
            flags |= 1
        if self.hogex or self.mweb_tx is not None:
            flags |= 8
        r = b""
        r += self.version.to_bytes(4, "little")
        if flags:
            dummy = []
            r += ser_vector(dummy)
            r += flags.to_bytes(1, "little")
        r += ser_vector(self.vin)
        r += ser_vector(self.vout)
        if flags & 1:
            if (len(self.wit.vtxinwit) != len(self.vin)):
                self.wit.vtxinwit = self.wit.vtxinwit[:len(self.vin)]
                for _ in range(len(self.wit.vtxinwit), len(self.vin)):
                    self.wit.vtxinwit.append(CTxInWitness())
            r += self.wit.serialize()
        if flags & 8:
            r += ser_mweb_tx(self.mweb_tx)
        r += self.nLockTime.to_bytes(4, "little")
        return r

    # Regular serialization is with mweb -- must explicitly
    # call serialize_with_witness to exclude mweb data or
    # serialize_without_witness to exclude witness & mweb data.
    def serialize(self):
        return self.serialize_with_mweb()

    @property
    def sha256(self):
        return self.txid_int

    @property
    def hash(self):
        return self.txid_hex

    def rehash(self):
        return self.txid_int

    def calc_sha256(self, with_witness=False):
        return self.wtxid_int if with_witness else self.txid_int

    @property
    def wtxid(self):
        """Return wtxid (transaction hash with witness) as little-endian bytes."""
        return hash256(self.serialize_with_witness())

    @property
    def wtxid_hex(self):
        """Return wtxid (transaction hash with witness) as hex string."""
        return self.wtxid[::-1].hex()

    @property
    def wtxid_int(self):
        """Return wtxid (transaction hash with witness) as integer."""
        return uint256_from_str(self.wtxid)

    @property
    def txid(self):
        """Return txid (transaction hash without witness) as little-endian bytes."""
        return hash256(self.serialize_without_witness())

    @property
    def txid_hex(self):
        """Return txid (transaction hash without witness) as hex string."""
        return self.txid[::-1].hex()

    @property
    def txid_int(self):
        """Return txid (transaction hash without witness) as integer."""
        return uint256_from_str(self.txid)

    def is_valid(self):
        for tout in self.vout:
            if tout.nValue < 0 or tout.nValue > MAX_MONEY:
                return False
        return True

    # Calculate the transaction weight using witness and non-witness
    # serialization size (does NOT use sigops).
    def get_weight(self):
        with_witness_size = len(self.serialize_with_witness())
        without_witness_size = len(self.serialize_without_witness())
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def get_vsize(self):
        return math.ceil(self.get_weight() / WITNESS_SCALE_FACTOR)

    def __repr__(self):
        return "CTransaction(version=%i vin=%s vout=%s wit=%s nLockTime=%i)" \
            % (self.version, repr(self.vin), repr(self.vout), repr(self.wit), self.nLockTime)

    def __eq__(self, other):
        return isinstance(other, CTransaction) and repr(self) == repr(other)


class CBlockHeader:
    __slots__ = ("hashMerkleRoot", "hashPrevBlock", "nBits", "nNonce",
                 "nTime", "nVersion", "auxpow")

    def __init__(self, header=None):
        if header is None:
            self.set_null()
        else:
            self.nVersion = header.nVersion
            self.hashPrevBlock = header.hashPrevBlock
            self.hashMerkleRoot = header.hashMerkleRoot
            self.nTime = header.nTime
            self.nBits = header.nBits
            self.nNonce = header.nNonce
            self.auxpow = getattr(header, "auxpow", None)

    def set_null(self):
        self.nVersion = 4
        self.hashPrevBlock = 0
        self.hashMerkleRoot = 0
        self.nTime = 0
        self.nBits = 0
        self.nNonce = 0
        self.auxpow = None

    def deserialize(self, f):
        self.nVersion = int.from_bytes(f.read(4), "little", signed=True)
        self.hashPrevBlock = deser_uint256(f)
        self.hashMerkleRoot = deser_uint256(f)
        self.nTime = int.from_bytes(f.read(8), "little")
        self.nBits = int.from_bytes(f.read(4), "little")
        self.nNonce = int.from_bytes(f.read(8), "little")
        if (self.nVersion & 0x100) != 0:
            from test_framework.auxpow import deserialize_auxpow
            self.auxpow = deserialize_auxpow(f)
        else:
            self.auxpow = None

    def serialize(self):
        r = self._serialize_header()
        if (self.nVersion & 0x100) != 0 and self.auxpow is not None:
            r += self.auxpow
        return r

    def _serialize_header(self):
        r = b""
        r += self.nVersion.to_bytes(4, "little", signed=True)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += self.nTime.to_bytes(8, "little")
        r += self.nBits.to_bytes(4, "little")
        r += self.nNonce.to_bytes(8, "little")
        return r

    def _serialize_pre_pow_header(self):
        r = b""
        r += self.nVersion.to_bytes(4, "little", signed=True)
        r += ser_uint256(self.hashPrevBlock)
        r += ser_uint256(self.hashMerkleRoot)
        r += (0).to_bytes(8, "little")
        r += self.nBits.to_bytes(4, "little")
        r += (0).to_bytes(8, "little")
        return r

    @property
    def hash_hex(self):
        """Return block header hash as hex string."""
        return hash256(self._serialize_header())[::-1].hex()

    @property
    def hash_int(self):
        """Return block header hash as integer."""
        return uint256_from_str(hash256(self._serialize_header()))

    @property
    def hash(self):
        return self.hash_hex

    @property
    def sha256(self):
        return self.hash_int

    def calc_sha256(self):
        return self.hash_int

    def rehash(self):
        return self.hash_int

    @property
    def pow_hash_bytes(self):
        pre_pow = hash256(self._serialize_pre_pow_header())
        work_order = pre_pow + self.nTime.to_bytes(8, "little") + (b"\x00" * 32) + self.nNonce.to_bytes(8, "little")
        return kheavyhash(work_order)

    @property
    def pow_hash_int(self):
        return uint256_from_str(self.pow_hash_bytes)

    def is_valid_pow(self):
        return self.pow_hash_int <= uint256_from_compact(self.nBits)

    def solve(self):
        while not self.is_valid_pow():
            self.nNonce += 1

    def __repr__(self):
        return "CBlockHeader(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime // 1000 if self.nTime > 10**11 else self.nTime), self.nBits, self.nNonce)

    def __eq__(self, other):
        if not isinstance(other, CBlockHeader):
            return NotImplemented
        return (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot, self.nTime, self.nBits, self.nNonce) == (
            other.nVersion, other.hashPrevBlock, other.hashMerkleRoot, other.nTime, other.nBits, other.nNonce)

BLOCK_HEADER_SIZE = len(CBlockHeader().serialize())
assert_equal(BLOCK_HEADER_SIZE, 88)

class CBlock(CBlockHeader):
    __slots__ = ("vtx", "mweb_block")

    def __init__(self, header=None):
        super().__init__(header)
        self.vtx = []
        self.mweb_block = None

    def deserialize(self, f):
        super().deserialize(f)
        self.vtx = deser_vector(f, CTransaction)
        if len(self.vtx) > 0 and self.vtx[-1].hogex:
            self.mweb_block = deser_mweb_block(f)

    def serialize(self, with_witness=True, with_mweb=None):
        r = b""
        r += super().serialize()
        if with_mweb is None:
            with_mweb = any(tx.hogex or tx.mweb_tx is not None for tx in self.vtx)
        if with_mweb and with_witness:
            r += ser_vector(self.vtx, "serialize_with_mweb")
            if len(self.vtx) > 0 and self.vtx[-1].hogex:
                r += ser_mweb_block(self.mweb_block)
        elif with_witness:
            r += ser_vector(self.vtx, "serialize_with_witness")
        else:
            r += ser_vector(self.vtx, "serialize_without_witness")
        return r

    # Calculate the merkle root given a vector of transaction hashes
    @classmethod
    def get_merkle_root(cls, hashes):
        while len(hashes) > 1:
            newhashes = []
            for i in range(0, len(hashes), 2):
                i2 = min(i+1, len(hashes)-1)
                newhashes.append(hash256(hashes[i] + hashes[i2]))
            hashes = newhashes
        return uint256_from_str(hashes[0])

    def calc_merkle_root(self):
        hashes = []
        for tx in self.vtx:
            hashes.append(ser_uint256(tx.txid_int))
        return self.get_merkle_root(hashes)

    def calc_witness_merkle_root(self):
        # For witness root purposes, the hash of the
        # coinbase, with witness, is defined to be 0...0
        hashes = [ser_uint256(0)]

        for tx in self.vtx[1:]:
            # Calculate the hashes with witness data
            hashes.append(ser_uint256(tx.wtxid_int))

        return self.get_merkle_root(hashes)

    def is_valid(self):
        target = uint256_from_compact(self.nBits)
        if self.pow_hash_int > target:
            return False
        for tx in self.vtx:
            if not tx.is_valid():
                return False
        if self.calc_merkle_root() != self.hashMerkleRoot:
            return False
        return True

    def solve(self):
        target = uint256_from_compact(self.nBits)
        while self.pow_hash_int > target:
            self.nNonce += 1

    # Calculate the block weight using witness and non-witness
    # serialization size (does NOT use sigops).
    def get_weight(self):
        with_witness_size = len(self.serialize(with_witness=True))
        without_witness_size = len(self.serialize(with_witness=False))
        return (WITNESS_SCALE_FACTOR - 1) * without_witness_size + with_witness_size

    def __repr__(self):
        return "CBlock(nVersion=%i hashPrevBlock=%064x hashMerkleRoot=%064x nTime=%s nBits=%08x nNonce=%08x vtx=%s)" \
            % (self.nVersion, self.hashPrevBlock, self.hashMerkleRoot,
               time.ctime(self.nTime), self.nBits, self.nNonce, repr(self.vtx))


class PrefilledTransaction:
    __slots__ = ("index", "tx")

    def __init__(self, index=0, tx = None):
        self.index = index
        self.tx = tx

    def deserialize(self, f):
        self.index = deser_compact_size(f)
        self.tx = CTransaction()
        self.tx.deserialize(f)

    def serialize(self, with_witness=True, with_mweb=True):
        r = b""
        r += ser_compact_size(self.index)
        if with_witness and with_mweb:
            r += self.tx.serialize_with_mweb()
        elif with_witness:
            r += self.tx.serialize_with_witness()
        else:
            r += self.tx.serialize_without_witness()
        return r

    def serialize_without_witness(self):
        return self.serialize(with_witness=False, with_mweb=False)

    def serialize_with_witness(self):
        return self.serialize(with_witness=True, with_mweb=False)

    def serialize_with_mweb(self):
        return self.serialize(with_witness=True, with_mweb=True)

    def __repr__(self):
        return "PrefilledTransaction(index=%d, tx=%s)" % (self.index, repr(self.tx))


# This is what we send on the wire, in a cmpctblock message.
class P2PHeaderAndShortIDs:
    __slots__ = ("header", "nonce", "prefilled_txn", "prefilled_txn_length",
                 "shortids", "shortids_length", "mweb_block")

    def __init__(self):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids_length = 0
        self.shortids = []
        self.prefilled_txn_length = 0
        self.prefilled_txn = []
        self.mweb_block = None

    def deserialize(self, f):
        self.header.deserialize(f)
        self.nonce = int.from_bytes(f.read(8), "little")
        self.shortids_length = deser_compact_size(f)
        for _ in range(self.shortids_length):
            # shortids are defined to be 6 bytes in the spec, so append
            # two zero bytes and read it in as an 8-byte number
            self.shortids.append(int.from_bytes(f.read(6) + b'\x00\x00', "little"))
        self.prefilled_txn = deser_vector(f, PrefilledTransaction)
        self.prefilled_txn_length = len(self.prefilled_txn)

        if f.tell() < len(f.getbuffer()):
            self.mweb_block = deser_mweb_block(f)
        else:
            self.mweb_block = None

    def serialize(self, version=1):
        r = b""
        r += self.header.serialize()
        r += self.nonce.to_bytes(8, "little")
        r += ser_compact_size(self.shortids_length)
        for x in self.shortids:
            r += x.to_bytes(8, "little")[0:6]
        if version >= 3:
            r += ser_vector(self.prefilled_txn, "serialize_with_mweb")
            r += ser_mweb_block(self.mweb_block)
        elif version == 2:
            r += ser_vector(self.prefilled_txn, "serialize_with_witness")
        else:
            r += ser_vector(self.prefilled_txn, "serialize_without_witness")
        return r

    def __repr__(self):
        return "P2PHeaderAndShortIDs(header=%s, nonce=%d, shortids_length=%d, shortids=%s, prefilled_txn_length=%d, prefilledtxn=%s" % (repr(self.header), self.nonce, self.shortids_length, repr(self.shortids), self.prefilled_txn_length, repr(self.prefilled_txn))


# P2P version of the above that will use witness serialization (for compact
# block version 2)
class P2PHeaderAndShortWitnessIDs(P2PHeaderAndShortIDs):
    __slots__ = ()
    def serialize(self):
        return super().serialize(version=2)


class P2PHeaderAndShortMWEBIDs(P2PHeaderAndShortIDs):
    __slots__ = ()
    def serialize(self):
        return super().serialize(version=3)

# Calculate the BIP 152-compact blocks shortid for a given transaction hash
def calculate_shortid(k0, k1, tx_hash):
    expected_shortid = siphash256(k0, k1, tx_hash)
    expected_shortid &= 0x0000ffffffffffff
    return expected_shortid


# This version gets rid of the array lengths, and reinterprets the differential
# encoding into indices that can be used for lookup.
class HeaderAndShortIDs:
    __slots__ = ("header", "nonce", "prefilled_txn", "shortids", "use_witness", "mweb_block")

    def __init__(self, p2pheaders_and_shortids = None):
        self.header = CBlockHeader()
        self.nonce = 0
        self.shortids = []
        self.prefilled_txn = []
        self.use_witness = False
        self.mweb_block = None

        if p2pheaders_and_shortids is not None:
            self.header = p2pheaders_and_shortids.header
            self.nonce = p2pheaders_and_shortids.nonce
            self.shortids = p2pheaders_and_shortids.shortids
            last_index = -1
            for x in p2pheaders_and_shortids.prefilled_txn:
                self.prefilled_txn.append(PrefilledTransaction(x.index + last_index + 1, x.tx))
                last_index = self.prefilled_txn[-1].index

    # MWEB: when set, compact blocks without an MWEB block are also serialized
    # as version 3, with an empty MWEB block field, as a node with NODE_MWEB expects.
    serialize_mweb = False

    def to_p2p(self):
        if self.mweb_block is not None or self.serialize_mweb:
            ret = P2PHeaderAndShortMWEBIDs()
        elif self.use_witness:
            ret = P2PHeaderAndShortWitnessIDs()
        else:
            ret = P2PHeaderAndShortIDs()
        ret.header = self.header
        ret.nonce = self.nonce
        ret.shortids_length = len(self.shortids)
        ret.shortids = self.shortids
        ret.mweb_block = self.mweb_block
        ret.prefilled_txn_length = len(self.prefilled_txn)
        ret.prefilled_txn = []
        last_index = -1
        for x in self.prefilled_txn:
            ret.prefilled_txn.append(PrefilledTransaction(x.index - last_index - 1, x.tx))
            last_index = x.index
        return ret

    def get_siphash_keys(self):
        header_nonce = self.header.serialize()
        header_nonce += self.nonce.to_bytes(8, "little")
        hash_header_nonce_as_str = sha256(header_nonce)
        key0 = int.from_bytes(hash_header_nonce_as_str[0:8], "little")
        key1 = int.from_bytes(hash_header_nonce_as_str[8:16], "little")
        return [ key0, key1 ]

    # Version 2 compact blocks use wtxid in shortids (rather than txid)
    def initialize_from_block(self, block, nonce=0, prefill_list=None, use_witness=False, version=1):
        if prefill_list is None:
            prefill_list = [0]
            # MWEB: the node prefills the HogEx, which is never in a mempool.
            if version >= 3 and block.mweb_block is not None and len(block.vtx) >= 2 and block.vtx[-1].hogex:
                prefill_list.append(len(block.vtx) - 1)
        self.header = CBlockHeader(block)
        self.nonce = nonce
        self.prefilled_txn = [ PrefilledTransaction(i, block.vtx[i]) for i in prefill_list ]
        self.shortids = []
        self.use_witness = use_witness or version >= 2
        self.mweb_block = block.mweb_block if version >= 3 else None
        [k0, k1] = self.get_siphash_keys()
        for i in range(len(block.vtx)):
            if i not in prefill_list:
                tx_hash = block.vtx[i].txid_int
                if self.use_witness:
                    tx_hash = block.vtx[i].wtxid_int
                self.shortids.append(calculate_shortid(k0, k1, tx_hash))

    def __repr__(self):
        return "HeaderAndShortIDs(header=%s, nonce=%d, shortids=%s, prefilledtxn=%s" % (repr(self.header), self.nonce, repr(self.shortids), repr(self.prefilled_txn))


class BlockTransactionsRequest:
    __slots__ = ("blockhash", "indexes")

    def __init__(self, blockhash=0, indexes = None):
        self.blockhash = blockhash
        self.indexes = indexes if indexes is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        indexes_length = deser_compact_size(f)
        for _ in range(indexes_length):
            self.indexes.append(deser_compact_size(f))

    def serialize(self):
        r = b""
        r += ser_uint256(self.blockhash)
        r += ser_compact_size(len(self.indexes))
        for x in self.indexes:
            r += ser_compact_size(x)
        return r

    # helper to set the differentially encoded indexes from absolute ones
    def from_absolute(self, absolute_indexes):
        self.indexes = []
        last_index = -1
        for x in absolute_indexes:
            self.indexes.append(x-last_index-1)
            last_index = x

    def to_absolute(self):
        absolute_indexes = []
        last_index = -1
        for x in self.indexes:
            absolute_indexes.append(x+last_index+1)
            last_index = absolute_indexes[-1]
        return absolute_indexes

    def __repr__(self):
        return "BlockTransactionsRequest(hash=%064x indexes=%s)" % (self.blockhash, repr(self.indexes))


class BlockTransactions:
    __slots__ = ("blockhash", "transactions")

    def __init__(self, blockhash=0, transactions = None):
        self.blockhash = blockhash
        self.transactions = transactions if transactions is not None else []

    def deserialize(self, f):
        self.blockhash = deser_uint256(f)
        self.transactions = deser_vector(f, CTransaction)

    def serialize(self, with_witness=True, with_mweb=True):
        r = b""
        r += ser_uint256(self.blockhash)
        if with_mweb and with_witness:
            r += ser_vector(self.transactions, "serialize_with_mweb")
        elif with_witness:
            r += ser_vector(self.transactions, "serialize_with_witness")
        else:
            r += ser_vector(self.transactions, "serialize_without_witness")
        return r

    def __repr__(self):
        return "BlockTransactions(hash=%064x transactions=%s)" % (self.blockhash, repr(self.transactions))


class CPartialMerkleTree:
    __slots__ = ("nTransactions", "vBits", "vHash")

    def __init__(self):
        self.nTransactions = 0
        self.vHash = []
        self.vBits = []

    def deserialize(self, f):
        self.nTransactions = int.from_bytes(f.read(4), "little")
        self.vHash = deser_uint256_vector(f)
        vBytes = deser_string(f)
        self.vBits = []
        for i in range(len(vBytes) * 8):
            self.vBits.append(vBytes[i//8] & (1 << (i % 8)) != 0)

    def serialize(self):
        r = b""
        r += self.nTransactions.to_bytes(4, "little")
        r += ser_uint256_vector(self.vHash)
        vBytesArray = bytearray([0x00] * ((len(self.vBits) + 7)//8))
        for i in range(len(self.vBits)):
            vBytesArray[i // 8] |= self.vBits[i] << (i % 8)
        r += ser_string(bytes(vBytesArray))
        return r

    def __repr__(self):
        return "CPartialMerkleTree(nTransactions=%d, vHash=%s, vBits=%s)" % (self.nTransactions, repr(self.vHash), repr(self.vBits))


class CMerkleBlock:
    __slots__ = ("header", "txn")

    def __init__(self):
        self.header = CBlockHeader()
        self.txn = CPartialMerkleTree()

    def deserialize(self, f):
        self.header.deserialize(f)
        self.txn.deserialize(f)

    def serialize(self):
        r = b""
        r += self.header.serialize()
        r += self.txn.serialize()
        return r

    def __repr__(self):
        return "CMerkleBlock(header=%s, txn=%s)" % (repr(self.header), repr(self.txn))


# Objects that correspond to messages on the wire
class msg_version:
    __slots__ = ("addrFrom", "addrTo", "nNonce", "relay", "nServices",
                 "nStartingHeight", "nTime", "nVersion", "strSubVer")
    msgtype = b"version"

    def __init__(self):
        self.nVersion = 0
        self.nServices = 0
        self.nTime = int(time.time())
        self.addrTo = CAddress()
        self.addrFrom = CAddress()
        self.nNonce = random.getrandbits(64)
        self.strSubVer = ''
        self.nStartingHeight = -1
        self.relay = 0

    def deserialize(self, f):
        self.nVersion = int.from_bytes(f.read(4), "little", signed=True)
        self.nServices = int.from_bytes(f.read(8), "little")
        self.nTime = int.from_bytes(f.read(8), "little", signed=True)
        self.addrTo = CAddress()
        self.addrTo.deserialize(f, with_time=False)

        self.addrFrom = CAddress()
        self.addrFrom.deserialize(f, with_time=False)
        self.nNonce = int.from_bytes(f.read(8), "little")
        self.strSubVer = deser_string(f).decode('utf-8')

        self.nStartingHeight = int.from_bytes(f.read(4), "little", signed=True)

        # Relay field is optional for version 70001 onwards
        # But, unconditionally check it to match behaviour in bitcoind
        self.relay = int.from_bytes(f.read(1), "little")  # f.read(1) may return an empty b''

    def serialize(self):
        r = b""
        r += self.nVersion.to_bytes(4, "little", signed=True)
        r += self.nServices.to_bytes(8, "little")
        r += self.nTime.to_bytes(8, "little", signed=True)
        r += self.addrTo.serialize(with_time=False)
        r += self.addrFrom.serialize(with_time=False)
        r += self.nNonce.to_bytes(8, "little")
        r += ser_string(self.strSubVer.encode('utf-8'))
        r += self.nStartingHeight.to_bytes(4, "little", signed=True)
        r += self.relay.to_bytes(1, "little")
        return r

    def __repr__(self):
        return 'msg_version(nVersion=%i nServices=%i nTime=%s addrTo=%s addrFrom=%s nNonce=0x%016X strSubVer=%s nStartingHeight=%i relay=%i)' \
            % (self.nVersion, self.nServices, time.ctime(self.nTime),
               repr(self.addrTo), repr(self.addrFrom), self.nNonce,
               self.strSubVer, self.nStartingHeight, self.relay)


class msg_verack:
    __slots__ = ()
    msgtype = b"verack"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_verack()"


class msg_addr:
    __slots__ = ("addrs",)
    msgtype = b"addr"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress)

    def serialize(self):
        return ser_vector(self.addrs)

    def __repr__(self):
        return "msg_addr(addrs=%s)" % (repr(self.addrs))


class msg_addrv2:
    __slots__ = ("addrs",)
    msgtype = b"addrv2"

    def __init__(self):
        self.addrs = []

    def deserialize(self, f):
        self.addrs = deser_vector(f, CAddress, "deserialize_v2")

    def serialize(self):
        return ser_vector(self.addrs, "serialize_v2")

    def __repr__(self):
        return "msg_addrv2(addrs=%s)" % (repr(self.addrs))


class msg_sendaddrv2:
    __slots__ = ()
    msgtype = b"sendaddrv2"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_sendaddrv2()"


class msg_inv:
    __slots__ = ("inv",)
    msgtype = b"inv"

    def __init__(self, inv=None):
        if inv is None:
            self.inv = []
        else:
            self.inv = inv

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_inv(inv=%s)" % (repr(self.inv))


class msg_getdata:
    __slots__ = ("inv",)
    msgtype = b"getdata"

    def __init__(self, inv=None):
        self.inv = inv if inv is not None else []

    def deserialize(self, f):
        self.inv = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.inv)

    def __repr__(self):
        return "msg_getdata(inv=%s)" % (repr(self.inv))


class msg_getblocks:
    __slots__ = ("locator", "hashstop")
    msgtype = b"getblocks"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getblocks(locator=%s hashstop=%064x)" \
            % (repr(self.locator), self.hashstop)


class msg_tx:
    __slots__ = ("tx",)
    msgtype = b"tx"

    def __init__(self, tx=None):
        if tx is None:
            self.tx = CTransaction()
        else:
            self.tx = tx

    def deserialize(self, f):
        self.tx.deserialize(f)

    def serialize(self):
        return self.tx.serialize_with_mweb()

    def __repr__(self):
        return "msg_tx(tx=%s)" % (repr(self.tx))

class msg_wtxidrelay:
    __slots__ = ()
    msgtype = b"wtxidrelay"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_wtxidrelay()"


class msg_no_witness_tx(msg_tx):
    __slots__ = ()

    def serialize(self):
        return self.tx.serialize_without_witness()


class msg_no_mweb_tx(msg_tx):
    __slots__ = ()

    def serialize(self):
        return self.tx.serialize_with_witness()


class msg_block:
    __slots__ = ("block",)
    msgtype = b"block"

    def __init__(self, block=None):
        if block is None:
            self.block = CBlock()
        else:
            self.block = block

    def deserialize(self, f):
        self.block.deserialize(f)

    def serialize(self):
        return self.block.serialize()

    def __repr__(self):
        return "msg_block(block=%s)" % (repr(self.block))


# Generic type to control the raw bytes sent over the wire.
# The msgtype and the data must be provided.
class msg_generic:
    __slots__ = ("msgtype", "data")

    def __init__(self, msgtype, data=None):
        self.msgtype = msgtype
        self.data = data

    def serialize(self):
        return self.data

    def __repr__(self):
        return "msg_generic()"


class msg_no_witness_block(msg_block):
    __slots__ = ()
    def serialize(self):
        return self.block.serialize(with_witness=False, with_mweb=False)


class msg_no_mweb_block(msg_block):
    __slots__ = ()
    def serialize(self):
        return self.block.serialize(with_witness=True, with_mweb=False)


class msg_getaddr:
    __slots__ = ()
    msgtype = b"getaddr"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_getaddr()"


class msg_ping:
    __slots__ = ("nonce",)
    msgtype = b"ping"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = int.from_bytes(f.read(8), "little")

    def serialize(self):
        r = b""
        r += self.nonce.to_bytes(8, "little")
        return r

    def __repr__(self):
        return "msg_ping(nonce=%08x)" % self.nonce


class msg_pong:
    __slots__ = ("nonce",)
    msgtype = b"pong"

    def __init__(self, nonce=0):
        self.nonce = nonce

    def deserialize(self, f):
        self.nonce = int.from_bytes(f.read(8), "little")

    def serialize(self):
        r = b""
        r += self.nonce.to_bytes(8, "little")
        return r

    def __repr__(self):
        return "msg_pong(nonce=%08x)" % self.nonce


class msg_mempool:
    __slots__ = ()
    msgtype = b"mempool"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_mempool()"


class msg_notfound:
    __slots__ = ("vec", )
    msgtype = b"notfound"

    def __init__(self, vec=None):
        self.vec = vec or []

    def deserialize(self, f):
        self.vec = deser_vector(f, CInv)

    def serialize(self):
        return ser_vector(self.vec)

    def __repr__(self):
        return "msg_notfound(vec=%s)" % (repr(self.vec))


class msg_sendheaders:
    __slots__ = ()
    msgtype = b"sendheaders"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_sendheaders()"


# getheaders message has
# number of entries
# vector of hashes
# hash_stop (hash of last desired block header, 0 to get as many as possible)
class msg_getheaders:
    __slots__ = ("hashstop", "locator",)
    msgtype = b"getheaders"

    def __init__(self):
        self.locator = CBlockLocator()
        self.hashstop = 0

    def deserialize(self, f):
        self.locator = CBlockLocator()
        self.locator.deserialize(f)
        self.hashstop = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.locator.serialize()
        r += ser_uint256(self.hashstop)
        return r

    def __repr__(self):
        return "msg_getheaders(locator=%s, stop=%064x)" \
            % (repr(self.locator), self.hashstop)


# headers message has
# <count> <vector of block headers>
class msg_headers:
    __slots__ = ("headers",)
    msgtype = b"headers"

    def __init__(self, headers=None):
        self.headers = headers if headers is not None else []

    def deserialize(self, f):
        # comment in bitcoind indicates these should be deserialized as blocks
        blocks = deser_vector(f, CBlock)
        for x in blocks:
            self.headers.append(CBlockHeader(x))

    def serialize(self):
        blocks = [CBlock(x) for x in self.headers]
        return ser_vector(blocks)

    def __repr__(self):
        return "msg_headers(headers=%s)" % repr(self.headers)


class msg_merkleblock:
    __slots__ = ("merkleblock",)
    msgtype = b"merkleblock"

    def __init__(self, merkleblock=None):
        if merkleblock is None:
            self.merkleblock = CMerkleBlock()
        else:
            self.merkleblock = merkleblock

    def deserialize(self, f):
        self.merkleblock.deserialize(f)

    def serialize(self):
        return self.merkleblock.serialize()

    def __repr__(self):
        return "msg_merkleblock(merkleblock=%s)" % (repr(self.merkleblock))


class msg_filterload:
    __slots__ = ("data", "nHashFuncs", "nTweak", "nFlags")
    msgtype = b"filterload"

    def __init__(self, data=b'00', nHashFuncs=0, nTweak=0, nFlags=0):
        self.data = data
        self.nHashFuncs = nHashFuncs
        self.nTweak = nTweak
        self.nFlags = nFlags

    def deserialize(self, f):
        self.data = deser_string(f)
        self.nHashFuncs = int.from_bytes(f.read(4), "little")
        self.nTweak = int.from_bytes(f.read(4), "little")
        self.nFlags = int.from_bytes(f.read(1), "little")

    def serialize(self):
        r = b""
        r += ser_string(self.data)
        r += self.nHashFuncs.to_bytes(4, "little")
        r += self.nTweak.to_bytes(4, "little")
        r += self.nFlags.to_bytes(1, "little")
        return r

    def __repr__(self):
        return "msg_filterload(data={}, nHashFuncs={}, nTweak={}, nFlags={})".format(
            self.data, self.nHashFuncs, self.nTweak, self.nFlags)


class msg_filteradd:
    __slots__ = ("data")
    msgtype = b"filteradd"

    def __init__(self, data):
        self.data = data

    def deserialize(self, f):
        self.data = deser_string(f)

    def serialize(self):
        r = b""
        r += ser_string(self.data)
        return r

    def __repr__(self):
        return "msg_filteradd(data={})".format(self.data)


class msg_filterclear:
    __slots__ = ()
    msgtype = b"filterclear"

    def __init__(self):
        pass

    def deserialize(self, f):
        pass

    def serialize(self):
        return b""

    def __repr__(self):
        return "msg_filterclear()"


class msg_feefilter:
    __slots__ = ("feerate",)
    msgtype = b"feefilter"

    def __init__(self, feerate=0):
        self.feerate = feerate

    def deserialize(self, f):
        self.feerate = int.from_bytes(f.read(8), "little")

    def serialize(self):
        r = b""
        r += self.feerate.to_bytes(8, "little")
        return r

    def __repr__(self):
        return "msg_feefilter(feerate=%08x)" % self.feerate


class msg_sendcmpct:
    __slots__ = ("announce", "version")
    msgtype = b"sendcmpct"

    def __init__(self, announce=False, version=2):
        self.announce = announce
        self.version = version

    def deserialize(self, f):
        self.announce = bool(int.from_bytes(f.read(1), "little"))
        self.version = int.from_bytes(f.read(8), "little")

    def serialize(self):
        r = b""
        r += int(self.announce).to_bytes(1, "little")
        r += self.version.to_bytes(8, "little")
        return r

    def __repr__(self):
        return "msg_sendcmpct(announce=%s, version=%lu)" % (self.announce, self.version)


class msg_cmpctblock:
    __slots__ = ("header_and_shortids",)
    msgtype = b"cmpctblock"

    def __init__(self, header_and_shortids = None):
        self.header_and_shortids = header_and_shortids

    def deserialize(self, f):
        self.header_and_shortids = P2PHeaderAndShortIDs()
        self.header_and_shortids.deserialize(f)

    def serialize(self):
        r = b""
        r += self.header_and_shortids.serialize()
        return r

    def __repr__(self):
        return "msg_cmpctblock(HeaderAndShortIDs=%s)" % repr(self.header_and_shortids)


class msg_getblocktxn:
    __slots__ = ("block_txn_request",)
    msgtype = b"getblocktxn"

    def __init__(self):
        self.block_txn_request = None

    def deserialize(self, f):
        self.block_txn_request = BlockTransactionsRequest()
        self.block_txn_request.deserialize(f)

    def serialize(self):
        r = b""
        r += self.block_txn_request.serialize()
        return r

    def __repr__(self):
        return "msg_getblocktxn(block_txn_request=%s)" % (repr(self.block_txn_request))


class msg_blocktxn:
    __slots__ = ("block_transactions",)
    msgtype = b"blocktxn"

    def __init__(self):
        self.block_transactions = BlockTransactions()

    def deserialize(self, f):
        self.block_transactions.deserialize(f)

    def serialize(self):
        r = b""
        r += self.block_transactions.serialize()
        return r

    def __repr__(self):
        return "msg_blocktxn(block_transactions=%s)" % (repr(self.block_transactions))


class msg_no_witness_blocktxn(msg_blocktxn):
    __slots__ = ()

    def serialize(self):
        return self.block_transactions.serialize(with_witness=False, with_mweb=False)


class msg_getcfilters:
    __slots__ = ("filter_type", "start_height", "stop_hash")
    msgtype =  b"getcfilters"

    def __init__(self, filter_type=None, start_height=None, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.start_height = int.from_bytes(f.read(4), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += self.start_height.to_bytes(4, "little")
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfilters(filter_type={:#x}, start_height={}, stop_hash={:x})".format(
            self.filter_type, self.start_height, self.stop_hash)

class msg_cfilter:
    __slots__ = ("filter_type", "block_hash", "filter_data")
    msgtype =  b"cfilter"

    def __init__(self, filter_type=None, block_hash=None, filter_data=None):
        self.filter_type = filter_type
        self.block_hash = block_hash
        self.filter_data = filter_data

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.block_hash = deser_uint256(f)
        self.filter_data = deser_string(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += ser_uint256(self.block_hash)
        r += ser_string(self.filter_data)
        return r

    def __repr__(self):
        return "msg_cfilter(filter_type={:#x}, block_hash={:x})".format(
            self.filter_type, self.block_hash)

class msg_getcfheaders:
    __slots__ = ("filter_type", "start_height", "stop_hash")
    msgtype =  b"getcfheaders"

    def __init__(self, filter_type=None, start_height=None, stop_hash=None):
        self.filter_type = filter_type
        self.start_height = start_height
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.start_height = int.from_bytes(f.read(4), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += self.start_height.to_bytes(4, "little")
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfheaders(filter_type={:#x}, start_height={}, stop_hash={:x})".format(
            self.filter_type, self.start_height, self.stop_hash)

class msg_cfheaders:
    __slots__ = ("filter_type", "stop_hash", "prev_header", "hashes")
    msgtype =  b"cfheaders"

    def __init__(self, filter_type=None, stop_hash=None, prev_header=None, hashes=None):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.prev_header = prev_header
        self.hashes = hashes

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)
        self.prev_header = deser_uint256(f)
        self.hashes = deser_uint256_vector(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += ser_uint256(self.stop_hash)
        r += ser_uint256(self.prev_header)
        r += ser_uint256_vector(self.hashes)
        return r

    def __repr__(self):
        return "msg_cfheaders(filter_type={:#x}, stop_hash={:x})".format(
            self.filter_type, self.stop_hash)

class msg_getcfcheckpt:
    __slots__ = ("filter_type", "stop_hash")
    msgtype =  b"getcfcheckpt"

    def __init__(self, filter_type=None, stop_hash=None):
        self.filter_type = filter_type
        self.stop_hash = stop_hash

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += ser_uint256(self.stop_hash)
        return r

    def __repr__(self):
        return "msg_getcfcheckpt(filter_type={:#x}, stop_hash={:x})".format(
            self.filter_type, self.stop_hash)

class msg_cfcheckpt:
    __slots__ = ("filter_type", "stop_hash", "headers")
    msgtype =  b"cfcheckpt"

    def __init__(self, filter_type=None, stop_hash=None, headers=None):
        self.filter_type = filter_type
        self.stop_hash = stop_hash
        self.headers = headers

    def deserialize(self, f):
        self.filter_type = int.from_bytes(f.read(1), "little")
        self.stop_hash = deser_uint256(f)
        self.headers = deser_uint256_vector(f)

    def serialize(self):
        r = b""
        r += self.filter_type.to_bytes(1, "little")
        r += ser_uint256(self.stop_hash)
        r += ser_uint256_vector(self.headers)
        return r

    def __repr__(self):
        return "msg_cfcheckpt(filter_type={:#x}, stop_hash={:x})".format(
            self.filter_type, self.stop_hash)

class msg_sendtxrcncl:
    __slots__ = ("version", "salt")
    msgtype = b"sendtxrcncl"

    def __init__(self):
        self.version = 0
        self.salt = 0

    def deserialize(self, f):
        self.version = int.from_bytes(f.read(4), "little")
        self.salt = int.from_bytes(f.read(8), "little")

    def serialize(self):
        r = b""
        r += self.version.to_bytes(4, "little")
        r += self.salt.to_bytes(8, "little")
        return r

    def __repr__(self):
        return "msg_sendtxrcncl(version=%lu, salt=%lu)" %\
            (self.version, self.salt)

class msg_feature:
    """FEATURE message for negotiating optional features."""
    __slots__ = ("feature_id", "feature_data")
    msgtype = b"feature"

    def __init__(self, feature_id="", feature_data=b""):
        self.feature_id = feature_id
        self.feature_data = feature_data

    def deserialize(self, f):
        self.feature_id = deser_string(f).decode()
        self.feature_data = deser_string(f)

    def serialize(self):
        r = ser_string(self.feature_id.encode())
        r += ser_string(self.feature_data)
        return r

    def __repr__(self):
        return f"msg_feature(feature_id={self.feature_id}, data={self.feature_data.hex()})"


class TestFrameworkScript(unittest.TestCase):
    def test_addrv2_encode_decode(self):
        def check_addrv2(ip, net):
            addr = CAddress()
            addr.net, addr.ip = net, ip
            ser = addr.serialize_v2()
            actual = CAddress()
            actual.deserialize_v2(BytesIO(ser))
            self.assertEqual(actual, addr)

        check_addrv2("1.65.195.98", CAddress.NET_IPV4)
        check_addrv2("2001:41f0::62:6974:636f:696e", CAddress.NET_IPV6)
        check_addrv2("2bqghnldu6mcug4pikzprwhtjjnsyederctvci6klcwzepnjd46ikjyd.onion", CAddress.NET_TORV3)
        check_addrv2("255fhcp6ajvftnyo7bwz3an3t4a4brhopm3bamyh2iu5r3gnr2rq.b32.i2p", CAddress.NET_I2P)
        check_addrv2("fc32:17ea:e415:c3bf:9808:149d:b5a2:c9aa", CAddress.NET_CJDNS)

    def test_varint_encode_decode(self):
        def check_varint(num, expected_encoding_hex):
            expected_encoding = bytes.fromhex(expected_encoding_hex)
            self.assertEqual(ser_varint(num), expected_encoding)
            self.assertEqual(deser_varint(BytesIO(expected_encoding)), num)

        # test cases from serialize_tests.cpp:varint_bitpatterns
        check_varint(0, "00")
        check_varint(0x7f, "7f")
        check_varint(0x80, "8000")
        check_varint(0x1234, "a334")
        check_varint(0xffff, "82fe7f")
        check_varint(0x123456, "c7e756")
        check_varint(0x80123456, "86ffc7e756")
        check_varint(0xffffffff, "8efefefe7f")
        check_varint(0xffffffffffffffff, "80fefefefefefefefe7f")

"""------------MWEB------------"""

def hex_reverse(h):
    return "".join(reversed([h[i:i+2] for i in range(0, len(h), 2)]))

class Hash:
    __slots__ = ("val")

    def __init__(self, val = 0):
        self.val = val

    @classmethod
    def from_hex(cls, hex_str):
        return cls(int(hex_str, 16))

    @classmethod
    def from_rev_hex(cls, hex_str):
        return cls(int(hex_reverse(hex_str), 16))

    @classmethod
    def from_byte_arr(cls, b):
        return cls(deser_uint256(BytesIO(b)))

    def to_hex(self):
        return self.serialize().hex()

    def to_byte_arr(self):
        return self.serialize()

    @classmethod
    def deserialize(cls, f):
        return cls(deser_uint256(f))

    def serialize(self):
        return ser_uint256(self.val)

    def __hash__(self):
        return hash(self.val)

    def __str__(self):
        return repr(self)

    def __repr__(self):
        return "Hash(val=0x{:x})".format(self.val)

    def __eq__(self, other):
        return isinstance(other, Hash) and self.val == other.val


def blake3(s):
    return Hash.from_rev_hex(BLAKE3.blake3(s).hexdigest())

def ser_mweb_block(b):
    if b is None:
        return struct.pack("B", 0)
    else:
        return struct.pack("B", 1) + b.serialize()

def deser_mweb_block(f):
    has_mweb = struct.unpack("B", f.read(1))[0]
    if has_mweb == 1:
        mweb_block = MWEBBlock()
        mweb_block.deserialize(f)
        return mweb_block
    else:
        return None

def ser_mweb_tx(t):
    if t is None:
        return struct.pack("B", 0)
    else:
        return struct.pack("B", 1) + t.serialize()

def deser_mweb_tx(f):
    has_mweb = struct.unpack("B", f.read(1))[0]
    if has_mweb == 1:
        mweb_tx = MWEBTransaction()
        mweb_tx.deserialize(f)
        return mweb_tx
    else:
        return None


class MWEBInput:
    __slots__ = ("features", "output_id", "commitment", "input_pubkey",
                "output_pubkey", "extradata", "signature", "hash")

    def __init__(self):
        self.features = 0
        self.output_id = Hash()
        self.commitment = None
        self.input_pubkey = None
        self.output_pubkey = None
        self.extradata = None
        self.signature = None
        self.hash = None

    def deserialize(self, f):
        self.features = struct.unpack("B", f.read(1))[0]
        self.output_id = Hash.deserialize(f)
        self.commitment = deser_pubkey(f)
        self.output_pubkey = deser_pubkey(f)
        if self.features & 1:
            self.input_pubkey = deser_pubkey(f)
        self.extradata = None
        if self.features & 2:
            self.extradata = deser_fixed_bytes(f, deser_compact_size(f))
        self.signature = deser_signature(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += struct.pack("B", self.features)
        r += self.output_id.serialize()
        r += ser_pubkey(self.commitment)
        r += ser_pubkey(self.output_pubkey)
        if self.features & 1:
            r += ser_pubkey(self.input_pubkey)
        if self.features & 2:
            r += ser_compact_size(len(self.extradata))
            r += ser_fixed_bytes(self.extradata, len(self.extradata))
        r += ser_signature(self.signature)
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

class MWEBOutputMessage:
    __slots__ = ("features", "key_exchange_pubkey", "view_tag", "masked_value",
                "masked_nonce", "extradata", "hash")

    def __init__(self):
        self.features = 0
        self.key_exchange_pubkey = None
        self.view_tag = 0
        self.masked_value = None
        self.masked_nonce = None
        self.extradata = None
        self.hash = None

    def deserialize(self, f):
        self.features = struct.unpack("B", f.read(1))[0]
        if self.features & 1:
            self.key_exchange_pubkey = deser_pubkey(f)
            self.view_tag = struct.unpack("B", f.read(1))[0]
            self.masked_value = struct.unpack("<q", f.read(8))[0]
            self.masked_nonce = deser_fixed_bytes(f, 16)
        self.extradata = None
        if self.features & 2:
            self.extradata = deser_fixed_bytes(f, deser_compact_size(f))
        self.rehash()

    def serialize(self):
        r = b""
        r += struct.pack("B", self.features)
        if self.features & 1:
            r += ser_pubkey(self.key_exchange_pubkey)
            r += struct.pack("B", self.view_tag)
            r += struct.pack("<q", self.masked_value)
            r += ser_fixed_bytes(self.masked_nonce, 16)
        if self.features & 2:
            r += ser_compact_size(len(self.extradata))
            r += ser_fixed_bytes(self.extradata, len(self.extradata))
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

class MWEBOutput:
    __slots__ = ("commitment", "sender_pubkey", "receiver_pubkey", "message",
                "proof", "signature", "hash")

    def __init__(self):
        self.commitment = None
        self.sender_pubkey = None
        self.receiver_pubkey = None
        self.message = MWEBOutputMessage()
        self.proof = None
        self.signature = None
        self.hash = None

    def deserialize(self, f):
        self.commitment = deser_pubkey(f)
        self.sender_pubkey = deser_pubkey(f)
        self.receiver_pubkey = deser_pubkey(f)
        self.message.deserialize(f)
        self.proof = deser_fixed_bytes(f, 675)
        self.signature = deser_signature(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += ser_pubkey(self.commitment)
        r += ser_pubkey(self.sender_pubkey)
        r += ser_pubkey(self.receiver_pubkey)
        r += self.message.serialize()
        r += ser_fixed_bytes(self.proof, 675)
        r += ser_signature(self.signature)
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

class MWEBCompactOutput:
    __slots__ = ("commitment", "sender_pubkey", "receiver_pubkey", "message",
                "proof_hash", "signature", "hash")

    def __init__(self):
        self.commitment = None
        self.sender_pubkey = None
        self.receiver_pubkey = None
        self.message = MWEBOutputMessage()
        self.proof_hash = None
        self.signature = None
        self.hash = None

    def deserialize(self, f):
        self.commitment = deser_pubkey(f)
        self.sender_pubkey = deser_pubkey(f)
        self.receiver_pubkey = deser_pubkey(f)
        self.message.deserialize(f)
        self.proof_hash = Hash.deserialize(f)
        self.signature = deser_signature(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += ser_pubkey(self.commitment)
        r += ser_pubkey(self.sender_pubkey)
        r += ser_pubkey(self.receiver_pubkey)
        r += self.message.serialize()
        r += self.proof_hash.serialize()
        r += ser_signature(self.signature)
        return r

    def __repr__(self):
        return "MWEBCompactOutput(commitment=%s)" % (repr(self.commitment))

class MWEBNetUTXO:
    __slots__ = ("leaf_index", "output", "output_format")

    def __init__(self, output_format=MWEB_UTXO_FORMAT_HASH_ONLY):
        self.leaf_index = 0
        self.output = None
        self.output_format = output_format

    def deserialize(self, f):
        self.leaf_index = deser_compact_size(f)
        if self.output_format == MWEB_UTXO_FORMAT_FULL:
            self.output = MWEBOutput()
            self.output.deserialize(f)
        elif self.output_format == MWEB_UTXO_FORMAT_HASH_ONLY:
            self.output = Hash.deserialize(f)
        elif self.output_format == MWEB_UTXO_FORMAT_COMPACT:
            self.output = MWEBCompactOutput()
            self.output.deserialize(f)
        else:
            raise ValueError("Unsupported MWEB UTXO serialization format %d" % self.output_format)

    def serialize(self):
        r = ser_compact_size(self.leaf_index)
        r += self.output.serialize()
        return r

    def __repr__(self):
        return "MWEBNetUTXO(leaf_index=%d, output=%s)" % (self.leaf_index, repr(self.output))


class MWEBKernel:
    __slots__ = ("features", "fee", "pegin", "pegouts", "lock_height",
                "stealth_excess", "extradata", "excess", "signature", "hash")

    def __init__(self):
        self.features = 0
        self.fee = None
        self.pegin = None
        self.pegouts = None
        self.lock_height = None
        self.stealth_excess = None
        self.extradata = None
        self.excess = None
        self.signature = None
        self.hash = None

    def deserialize(self, f):
        self.features = struct.unpack("B", f.read(1))[0]
        self.fee = None
        if self.features & 1:
            self.fee = deser_varint(f)
        self.pegin = None
        if self.features & 2:
            self.pegin = deser_varint(f)
        self.pegouts = None
        if self.features & 4:
            self.pegouts = deser_vector(f, MWEBPegOut)
        self.lock_height = None
        if self.features & 8:
            self.lock_height = deser_varint(f)
        self.stealth_excess = None
        if self.features & 16:
            self.stealth_excess = deser_pubkey(f)
        self.extradata = None
        if self.features & 32:
            self.extradata = deser_fixed_bytes(f, deser_compact_size(f))
        self.excess = deser_pubkey(f)
        self.signature = deser_signature(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += struct.pack("B", self.features)
        if self.features & 1:
            r += ser_varint(self.fee)
        if self.features & 2:
            r += ser_varint(self.pegin)
        if self.features & 4:
            r += ser_vector(self.pegouts)
        if self.features & 8:
            r += ser_varint(self.lock_height)
        if self.features & 16:
            r += ser_pubkey(self.stealth_excess)
        if self.features & 32:
            r += ser_compact_size(len(self.extradata))
            r += ser_fixed_bytes(self.extradata, len(self.extradata))
        r += ser_pubkey(self.excess)
        r += ser_signature(self.signature)
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

    def __repr__(self):
        return "MWEBKernel(features=%d, excess=%s)" % (self.features, repr(self.excess))


class MWEBPegOut:
    __slots__ = ("amount", "script_pubkey")

    def __init__(self):
        self.amount = 0
        self.script_pubkey = b""

    def deserialize(self, f):
        self.amount = deser_varint(f)
        self.script_pubkey = deser_string(f)

    def serialize(self):
        r = b""
        r += ser_varint(self.amount)
        r += ser_string(self.script_pubkey)
        return r

    def __repr__(self):
        return "MWEBPegOut(amount=%d, script_pubkey=%s)" % (self.amount, repr(self.script_pubkey))

class MWEBTxBody:
    __slots__ = ("inputs", "outputs", "kernels")

    def __init__(self):
        self.inputs = []
        self.outputs = []
        self.kernels = []

    def deserialize(self, f):
        self.inputs = deser_vector(f, MWEBInput)
        self.outputs = deser_vector(f, MWEBOutput)
        self.kernels = deser_vector(f, MWEBKernel)

    def serialize(self):
        r = b""
        r += ser_vector(self.inputs)
        r += ser_vector(self.outputs)
        r += ser_vector(self.kernels)
        return r

    def __repr__(self):
        return "MWEBTxBody(inputs=%s, outputs=%s, kernels=%s)" % (repr(self.inputs), repr(self.outputs), repr(self.kernels))


class MWEBTransaction:
    __slots__ = ("kernel_offset", "stealth_offset", "body", "hash")

    def __init__(self):
        self.kernel_offset = Hash()
        self.stealth_offset = Hash()
        self.body = MWEBTxBody()
        self.hash = None

    def deserialize(self, f):
        self.kernel_offset = Hash.deserialize(f)
        self.stealth_offset = Hash.deserialize(f)
        self.body.deserialize(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += self.kernel_offset.serialize()
        r += self.stealth_offset.serialize()
        r += self.body.serialize()
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

    def __repr__(self):
        return "MWEBTransaction(kernel_offset=%s, stealth_offset=%s, body=%s, hash=%s)" % (repr(self.kernel_offset), repr(self.stealth_offset), repr(self.body), repr(self.hash))

class MWEBHeader:
    __slots__ = ("height", "output_root", "kernel_root", "leafset_root",
                "kernel_offset", "stealth_offset", "num_txos", "num_kernels", "hash")

    def __init__(self):
        self.height = 0
        self.output_root = Hash()
        self.kernel_root = Hash()
        self.leafset_root = Hash()
        self.kernel_offset = Hash()
        self.stealth_offset = Hash()
        self.num_txos = 0
        self.num_kernels = 0
        self.hash = None

    def from_json(self, mweb_json):
        self.height = mweb_json['height']
        self.output_root = Hash.from_rev_hex(mweb_json['output_root'])
        self.kernel_root = Hash.from_rev_hex(mweb_json['kernel_root'])
        self.leafset_root = Hash.from_rev_hex(mweb_json['leaf_root'])
        self.kernel_offset = Hash.from_rev_hex(mweb_json['kernel_offset'])
        self.stealth_offset = Hash.from_rev_hex(mweb_json['stealth_offset'])
        self.num_txos = mweb_json['num_txos']
        self.num_kernels = mweb_json['num_kernels']
        self.rehash()

    def deserialize(self, f):
        self.height = deser_varint(f)
        self.output_root = Hash.deserialize(f)
        self.kernel_root = Hash.deserialize(f)
        self.leafset_root = Hash.deserialize(f)
        self.kernel_offset = Hash.deserialize(f)
        self.stealth_offset = Hash.deserialize(f)
        self.num_txos = deser_varint(f)
        self.num_kernels = deser_varint(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += ser_varint(self.height)
        r += self.output_root.serialize()
        r += self.kernel_root.serialize()
        r += self.leafset_root.serialize()
        r += self.kernel_offset.serialize()
        r += self.stealth_offset.serialize()
        r += ser_varint(self.num_txos)
        r += ser_varint(self.num_kernels)
        return r

    def rehash(self):
        self.hash = blake3(self.serialize())
        return self.hash.to_hex()

    def __repr__(self):
        return ("MWEBHeader(height=%d, output_root=%s, kernel_root=%s, leafset_root=%s, kernel_offset=%s, stealth_offset=%s, num_txos=%d, num_kernels=%d, hash=%s)" %
            (self.height, repr(self.output_root), repr(self.kernel_root), repr(self.leafset_root), repr(self.kernel_offset), repr(self.stealth_offset), self.num_txos, self.num_kernels, repr(self.hash)))

    def __eq__(self, other):
        return isinstance(other, MWEBHeader) and self.hash == other.hash

class MWEBBlock:
    __slots__ = ("header", "body")

    def __init__(self, header=None):
        if header is None:
            header = MWEBHeader()
        self.header = copy.deepcopy(header)
        self.body = MWEBTxBody()

    def deserialize(self, f):
        self.header.deserialize(f)
        self.body.deserialize(f)
        self.rehash()

    def serialize(self):
        r = b""
        r += self.header.serialize()
        r += self.body.serialize()
        return r

    def rehash(self):
        return self.header.rehash()

    def __repr__(self):
        return "MWEBBlock(header=%s, body=%s)" % (repr(self.header), repr(self.body))


class CMerkleBlockWithMWEB:
    __slots__ = ("merkle", "hogex", "mweb_header")

    def __init__(self):
        self.merkle = CMerkleBlock()
        self.hogex = CTransaction()
        self.mweb_header = MWEBHeader()

    def deserialize(self, f):
        self.merkle.deserialize(f)
        self.hogex.deserialize(f)
        self.mweb_header.deserialize(f)

    def serialize(self):
        r = b""
        r += self.merkle.serialize()
        r += self.hogex.serialize_with_mweb()
        r += self.mweb_header.serialize()
        return r

    def __repr__(self):
        return "CMerkleBlockWithMWEB(merkle=%s, hogex=%s, mweb_header=%s)" % (repr(self.merkle), repr(self.hogex), repr(self.mweb_header))


class msg_mwebheader:
    __slots__ = ("merkleblockwithmweb",)
    msgtype = b"mwebheader"

    def __init__(self, merkleblockwithmweb=None):
        if merkleblockwithmweb is None:
            merkleblockwithmweb = CMerkleBlockWithMWEB()
        self.merkleblockwithmweb = merkleblockwithmweb

    def deserialize(self, f):
        self.merkleblockwithmweb.deserialize(f)

    def serialize(self):
        return self.merkleblockwithmweb.serialize()

    def header_hash(self):
        self.merkleblockwithmweb.merkle.header.rehash()
        return self.merkleblockwithmweb.merkle.header.hash

    def __repr__(self):
        return "msg_mwebheader(merkleblockwithmweb=%s)" % (repr(self.merkleblockwithmweb))

class msg_mwebleafset:
    __slots__ = ("block_hash", "leafset")
    msgtype = b"mwebleafset"

    def __init__(self, block_hash=None, leafset=None):
        self.block_hash = block_hash
        self.leafset = leafset

    def deserialize(self, f):
        self.block_hash = Hash.deserialize(f)
        self.leafset = deser_fixed_bytes(f, deser_compact_size(f))

    def serialize(self):
        r = b""
        r += self.block_hash.serialize()
        r += ser_compact_size(len(self.leafset))
        r += ser_fixed_bytes(self.leafset, len(self.leafset))
        return r

    def __repr__(self):
        leafset_hex = ser_fixed_bytes(self.leafset, len(self.leafset)).hex() #encode(self.leafset, 'hex_codec').decode('ascii')
        return "msg_mwebleafset(block_hash=%s, leafset=%s%s)" % (repr(self.block_hash), repr(leafset_hex)[:50], "..." if len(leafset_hex) > 50 else "")

class msg_getmwebutxos:
    __slots__ = ("block_hash", "start_index", "num_requested", "output_format")
    msgtype = b"getmwebutxos"

    def __init__(self, block_hash=None, start_index=0, num_requested=0, output_format=0):
        self.block_hash = block_hash
        self.start_index = start_index
        self.num_requested = num_requested
        self.output_format = output_format

    def deserialize(self, f):
        self.block_hash = Hash.deserialize(f)
        self.start_index = deser_compact_size(f)
        self.num_requested = struct.unpack("<H", f.read(2))[0]
        self.output_format = struct.unpack("B", f.read(1))[0]

    def serialize(self):
        r = b""
        r += self.block_hash.serialize()
        r += ser_compact_size(self.start_index)
        r += struct.pack("<H", self.num_requested)
        r += struct.pack("B", self.output_format)
        return r

    def __repr__(self):
        return ("msg_getmwebutxos(block_hash=%s, start_index=%d, num_requested=%d, output_format=%d)" %
            (repr(self.block_hash), self.start_index, self.num_requested, self.output_format))


class msg_mwebutxos:
    __slots__ = ("block_hash", "start_index", "output_format", "utxos", "proof_hashes")
    msgtype = b"mwebutxos"

    def __init__(self, block_hash=None, start_index=0, output_format=0, utxos=None, proof_hashes=None):
        self.block_hash = block_hash
        self.start_index = start_index
        self.output_format = output_format
        self.utxos = utxos
        self.proof_hashes = proof_hashes

    def deserialize(self, f):
        self.block_hash = Hash.deserialize(f)
        self.start_index = deser_compact_size(f)
        self.output_format = struct.unpack("B", f.read(1))[0]

        utxos_len = deser_compact_size(f)
        self.utxos = []
        for _ in range(utxos_len):
            utxo = MWEBNetUTXO(self.output_format)
            utxo.deserialize(f)
            self.utxos.append(utxo)

        # Hash.deserialize constructs a new Hash rather than mutating an
        # instance, so the generic in-place vector decoder discards its value.
        self.proof_hashes = [Hash.deserialize(f) for _ in range(deser_compact_size(f))]

    def serialize(self):
        r = b""
        r += self.block_hash.serialize()
        r += ser_compact_size(self.start_index)
        r += struct.pack("B", self.output_format)
        r += ser_vector(self.utxos)
        r += ser_vector(self.proof_hashes)
        return r

    def __repr__(self):
        return ("msg_mwebutxos(block_hash=%s, start_index=%d, output_format=%d, utxos=%s, proof_hashes=%s)" %
            (repr(self.block_hash), self.start_index, self.output_format, repr(self.utxos), repr(self.proof_hashes)))
