# README for WSGI-USER

> *WSGI allows stacks of HTTP-processing layers to form a service.
> The HTTP User header expresses a client-side awareness of a username
> that it would like to access on the server, if specific resource are
> available.  The server may ignore this or modify its responses.*

WSGI-USER middleware filters traffic that holds a `HTTP_USER` environment
variable, taken literally from the `User` header, and transforms it into
a `LOCAL_USER` variable after a number of checks:

  * No colon `:` may occur in the `User` header
  * Percent decoding is removed (if the syntax is good)
  * By default, empty strings are passed
  * Syntax checking is applied to decide whether the `LOCAL_USER` passes.

To construct a callable object for a WSGI stack, instantiate the class
`WSGI_User`, providing it with an inner object and providing an outer
object.

The **ban on colons** in the plain `User` header forbids the use of the
"user:password" format that
[has been deprecated](https://tools.ietf.org/html/rfc3986#section-3.2.1)
for security reasons.  This is no ban on expressive freedom, but a colon
can only occur in escaped form, so that it cannot possibly be interpreted
as this deprecated form by intermediate software layers.  The `User` header
never carries password information.

The passing of **empty strings** is useful as a default user or to indicate
that no user has been selected yet, but that the HTTP channel can carry
the `User` header.  Knowing whether the `User` header is supported is
useful, so empty strings pass by default.  This can be overridden with
`empty_user=False` upon instantiation of `WSGI_User`.

The default **syntax check** validates against the format of a
[Network Access Identifier](https://tools.ietf.org/html/rfc7542#section-2.2)
because that has broad recognition as a username format.  If you prefer to
use another format, you can either supply a syntax string or a regular
expression object output by `re.compile` as a substitute.  Please remember
to scan between `^` and `$` and accept that empty strings are not checked
against your syntax.  You can pass the syntax as `user_syntax=...` upon
instantiation of `WSGI_User`.

Note that **percent decoding** does not guarantee more than a proper
syntax of two hex digits after every `%`.  After percent unescaping
there may be colons `:` in the output, as well as binary codes such
as 0x00 and 0xff bytes and illegal UTF-8 sequences.  This is why it is
a good idea to validate the input.  The NAI default syntax validates,
among others, that proper UTF-8 is being supplied.  The regular expression
for this is externally available as `re_utf8_xtra_char` covering
[UTF-8 sequences of 2, 3 or 4 bytes](https://tools.ietf.org/html/rfc3629#section-4)
and only excluding the 1-byte sequences that overlap ASCII codes
(and for good reason; ASCII often introduces grammar).


