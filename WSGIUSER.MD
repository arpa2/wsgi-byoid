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


## Support for Tilde Server Conventions

When servers want to reveal users, they can opt for a local convention
in the path name.  These are never useful to clients, though guesswork
is triggered by them.  The conceptual clarity of the `User` header
provides the semantics necessary for inductive processing, and is
thereby better for automation.

The tilde convention is implemented for paths that start with the pattern
`/~username` and continues with resources specific to the user.  The
beginning is stripped off the path and used as a `User` header value in
the `LOCAL_USER` variable.  Syntax checking is applied as always, but
stripping is always done.

The following extra flag influences this facility:

  * `map_tilde=True` maps the `/~username` form to a
    `User: username` header and remove the `/~username` form from
    the path component of the URI.  When the `User` header
    already exists, it is not overwritten but compared, and
    an error is reported when the values differ.


## Support for Basic Authentication

Before the `User` header was available, a pattern to address a user
was through Basic authentication, either with or without a password.
This habit conflates client-side and server-side notions of user names,
and invalidates more advanced patterns where clients are members that
address a group's resources, or someone else's as may be permitted
by an Access Control List.  The conflation is also the probably cause
of the common pattern where websites require a user to make a password
on their site, rather than invite them to
[Bring Your Own IDentity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html).

When sent without password, it may be interpreted as an attempt to
address a user under conflation of client-side and server-side notions
of user, and so it makes sense to send the `User` header for it.  This
is the default behaviour of WSGI-User, given that it is used for a
server that supposedly supports the header.  The Basic authentication
header without password is then removed.

When sent with password, it may be that the client is trying to
authenticate with a fixed password as a credential.  This form is
also translated like a `User` header, but the header is kept by
default, so it may also serve authentication with a client identity.

The translation does not involve % unescaping, because the Basic
header is sent under base64-encoding.  The one missing facility is
that no colon `:` is possible in the user name.  Syntax is checked,
as well as the check for empty user names.

If the `User` header is already provided, its value will be compared
and, upon differences, an error will be returned.

The following extra flags influence this facility:

  * `map_basic=True` maps Basic authentication with empty
    or filled passwords like is done for the `User` header,
    except for % unescaping; the header is removed when the
    password is empty.
  * `map_basic_always=False` does the same, but it also removes
    the form with a filled password (which means that further
    stages will ignore any such password).
  * `proxy_auth=False` is used to work as an HTTP proxy, rather
    than as an HTTP server.  This differentiates the header used.

