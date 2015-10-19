import base64
import hashlib
import re


__all__ = (
    'DEFAULT_ALOGRITHM',
    'RECOGNISED_ALGORITHMS',
    'generate',
    'parse',
)

DEFAULT_ALOGRITHM = 'sha384'

RECOGNISED_ALGORITHMS = (
    'sha512',
    'sha384',
    'sha256',
)

_INTEGRITY_PATTERN = re.compile(r'''
    [ \t]*                                  # RFC 5234 (ABNF): WSP
    (?P<algorithm>sha256|sha384|sha512)     # W3C CSP2: hash-algo
    -
    (?P<b58_digest>[a-zA-Z0-9+/]+[=]{0,2})  # W3C CSP2: base64-value
    (?P<options>\?[\041-\176]*)?            # RFC 5234 (ABNF): VCHAR
    [ \t]*                                  # RFC 5234 (ABNF): WSP
    ''',
    re.VERBOSE,
)


class Hash(object):
    def __new__(cls, algorithm, digest, options=''):
        self = object.__new__(cls)
        self._algorithm = algorithm
        self._digest = digest
        self._options = options
        return self

    @classmethod
    def fromresource(cls, resource, algorithm=DEFAULT_ALOGRITHM, options=''):
        if algorithm not in RECOGNISED_ALGORITHMS:
            raise ValueError
        hasher = hashlib.new(algorithm, resource)
        digest = hasher.digest()
        return cls(algorithm, digest, options)

    @classmethod
    def fromhash(cls, algorithm, b58_digest, options):
        digest = base64.standard_b64decode(b58_digest)
        return cls(algorithm, digest, options)

    @classmethod
    def fromhashexpr(cls, s):
        m = _INTEGRITY_PATTERN.match(s)
        if not m:
            raise ValueError
        algorithm = m.group('alogrithm')
        b58_digest = m.group('b58_digest')
        options = m.group('options')[1:] # Remove leading '?'
        return cls.fromhash(alogrithm, b58_digest, options)

    @property
    def algorithm(self):
        return self._algorithm

    @property
    def digest(self):
        return self._digest

    @property
    def options(self):
        return self._options

    @property
    def b58digest(self):
        return base64.standard_b64encode(self._digest).decode('ascii')

    def __repr__(self):
        return "%s.%s('%s', '%s', '%s')" % (self.__class__.__module__,
                                            self.__class__.__name__,
                                            self.algorithm, self.b58digest,
                                            self.options)

    def __str__(self):
        if not self.options:
            return '%s-%s' % (self.algorithm, self.b58digest)
        return '%s-%s?%s' % (self.algorithm, self.b58digest, self.options)

    def __eq__(self, other):
        if isinstance(other, Hash):
            return bool(self.algorithm == other.algorithm
                        and self.digest == other.digest
                        and self.options == other.options)
        return False

    def __hash__(self):
        return hash((self.algorithm, self.digest, self.options))


def generate(data, algorithms=(DEFAULT_ALOGRITHM,)):
    """Yields subresource integrity Hash objects for the given data &
    algorithms

    >>> for ihash in generate(b"alert('Hello, world.');"):
    ...     print ('%s %s' % (ihash.algorithm, ihash.b58digest))
    sha384 H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO

    >>> list(generate(b"alert('Hello, world.');", ['sha256', 'sha384']))
    ... # doctest: +ELLIPSIS, +NORMALIZE_WHITESPACE
    [subresource_integrity.Hash('sha256', 'qz.../Tng=', ''),
     subresource_integrity.Hash('sha384', 'H8BR...+eX6xO', '')]
    """
    return (Hash.fromresource(data, algorithm) for algorithm in algorithms)


def render(data, algorithms=(DEFAULT_ALOGRITHM,), seperator=' '):
    """Returns a subresource integrity string for the given data &
    algorithms

    >>> data = b"alert('Hello, world.');"
    >>> render(data)
    'sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO'

    >>> print(render(data, ['sha256', 'sha384'], seperator='\\n'))
    sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng=
    sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO
    """
    return seperator.join(str(ihash) for ihash in generate(data, algorithms))


def parse(integrity):
    """Returns a list of subresource integrity Hash objects parsed from a str

    >>> parse('  sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU= ')
    ... # doctest: +ELLIPSIS
    [subresource_integrity.Hash('sha256', '47DEQp...SuFU=', '')]

    Hash objects are put in descending order of algorithmic strength

    >>> parse('sha384-dOTZf16X8p34q2/kYyEFm0jh89uTjikhnzjeLeF0FHsEaYKb'
    ...       '1A1cv+Lyv4Hk8vHd'
    ...       ' '
    ...       'sha512-Q2bFTOhEALkN8hOms2FKTDLy7eugP2zFZ1T8LCvX42Fp3WoN'
    ...       'r3bjZSAHeOsHrbV1Fu9/A0EzCinRE7Af1ofPrw=='
    ... )
    ... # doctest: +ELLIPSIS, +NORMALIZE_WHITESPACE
    [subresource_integrity.Hash('sha512', 'Q2b...zCinRE7Af1ofPrw==', ''),
     subresource_integrity.Hash('sha384', 'dOT...Hk8vHd', '')]

    Unrecognised hash algorithms are discarded

    >>> parse('sha1-2jmj7l5rSw0yVb/vlWAYkK/YBwk=')
    []
    """
    matches = _INTEGRITY_PATTERN.findall(integrity)
    matches.sort(key=lambda t: RECOGNISED_ALGORITHMS.index(t[0]))
    return [Hash.fromhash(*match) for match in matches]

