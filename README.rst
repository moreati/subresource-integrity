=====================
subresource-integrity
=====================

A Python package to create and parse `Subresource Integrity`_ values.

Installation
============

.. code:: shell

    pip install subresource-integrity

Usage
=====

Render an integrity value, given the content

.. code:: python

    >>> import subresource_integrity as integrity
    >>> data = b"alert('Hello, world.');"
    >>> integrity.render(data)
    'sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO'

Render multiple integrity values for the same content

.. code:: python

    >>> hashes = list(integrity.generate(data, ['sha384', 'sha256']))
    >>> [str(h) for h in hashes] # doctest: +NORMALIZE_WHITESPACE
    ['sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO',
     'sha256-qznLcsROx4GACP2dm0UCKCzCG+HiZ1guq6ZZDob/Tng=']

Parse several space-delimited integrity values, and iterate of them

.. code:: python

    >>> parsed = integrity.parse(' sha256-47DEQpj8HBSa+/TImW+5JCeu'
    ...                          'QeRkm5NMpJWZG3hSuFU= ')
    >>> parsed # doctest: +ELLIPSIS
    [subresource_integrity.Hash('sha256', '47DEQp...SuFU=', '')]
    >>> [str(h) for h in parsed]
    ['sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=']

.. _subresource integrity: https://en.wikipedia.org/wiki/Subresource_Integrity
