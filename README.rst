=====================
subresource-integrity
=====================

A Python package to create and parse `subresource integrity` values

Usage
=====

.. code:: python

    >>> import subresource_integrity as integrity
    >>> data = b"alert('Hello, world.');"
    >>> integrity.render(data)
    'sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO'

    >>> hashes = list(integrity.generate(data, ['sha384', 'sha256']))
    >>> [str(h) for h in hashes] # doctest: +NORMALIZE_WHITESPACE
    ['sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO',
     'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng=']

    >>> parsed = integrity.parse(' sha256-47DEQpj8HBSa+/TImW+5JCeu'
    ...                          'QeRkm5NMpJWZG3hSuFU= ')
    >>> parsed # doctest: +ELLIPSIS
    [subresource_integrity.Hash('sha256', '47DEQp...SuFU=', '')]
    >>> [str(h) for h in parsed]
    ['sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=']

