# README for ARPA2 WSGI middleware

> *WSGI enables middleware, which is a perfect place
> for enforcing ARPA2 Identities, ranging from
> authentication to authorisation through access control.*

**Background links:**

  * [InternetWide Identity Design](http://internetwide.org/tag/identity.html)
  * [ARPA2 Identity](http://donai.arpa2.net) (formerly known as DoNAI)
    supports
    [many forms](http://internetwide.org/blog/2015/04/23/id-3-idforms.html)
    and
    [several tricks](http://internetwide.org/blog/2015/04/24/id-4-tricks.html)
  * [ARPA2 Selector](http://donai.arpa2.net/selector.html)
  * [Access Control](http://donai.arpa2.net/acl.html)
    with
    [efficient implementation](http://donai.arpa2.net/acl-impl.html)
    and a design for
    [backend protocols](http://idp.arpa2.net/diameter.html).


## HTTP SASL handled with WSGI SASL

Most protocols that require authentication make use of the SASL
protocol.  Maybe it is better to say that SASL is a kind of
tunnel that passes through a protocol to exchange authentication
in a flexible manner.  Most importantly, the mechanisms can be
plugged into software independent of the protocol that uses SASL
and one infrastructure can be shared by all the protocols.

HTTP has not had SASL implemented.  We have
[specified HTTP SASL](https://tools.ietf.org/html/draft-vanrein-httpauth-sasl-00)
to fix that, and stop the ongoing need for authentication systems
built into the (rather insecure) JavaScript namespace.
We are implementing it with a few Java demonstrations, as well
as a
[browser extension](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)
with
[native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
so we may reuse desktop credentials from a trusted application
outside the browser.  Yes, that includes one's Kerberos login
and yes, it enables the use of
[pseudonyms during realm crossover](http://internetwide.org/blog/2015/04/22/id-2-byoid.html).

We are hoping to develop a Python WSGI component for the server side.
It would sit between the web server and WSGI application, and
detect 401 or 407 responses, annotate them with SASL authentication
option and hope to find a browser that responds to the option of
SASL authentication.

**Current status:** There is no reasonable support for server-side
SASL at this moment.  We have asked others to help out with this.


## HTTP User handled with WSGI User

Authentication users are client identities.  Most protocols also recognise
a user on the server side, but HTTP does not.  And if it does, it is
supposed to be the same as the client identity, which is thereby forced to
fall under the server's realm.  We see the resuls everywhere; the web asks
you to create an account on many sites you visit.  This is not practical.

We therefore proposed an extension to HTTP that explicitly indicates the
User as part of the resource name space identification on the server or,
in URI terms, of the authority.  If we move towards peer-to-peer HTTP
service, this is going to be
[helpful for routing requests](https://github.com/tlswg/draft-ietf-tls-esni/issues/206),
perhaps in combination with encrypted portions in the initial TLS messages.

This extension to HTTP is straightforward, and it has been implemented
for WSGI in the `WSGI_User` class.  This reads the `User` header,
removes `%`-escapes, applies a syntax check that defaults to the
[NAI syntax](https://tools.ietf.org/html/rfc7542#section-2.2)
with a default-on option to also allow empty strings, and if it
matches, passes the value in a `LOCAL_USER` environment variable
and will signal the impact on caching by adding a `Vary: User`
response header.

**Current status:** The code performs well in our test programs.
Please try it live and report to us!

### Idea: Basic Authentication maps to User

The old adagio for addressing a user on the server was to use
Basic authentication, possibly without a password.  The headers
that send this format can be mapped to the `User` header to allow
trivial backward compatibility.  When no password is supplied,
it is furthermore safe to remove this authenitcation header.
An option can inidcate whether to also remove the header if
an ignored password is to be removed.

This might be done with flags:

  * `map_basic=False` would map Basic authentication with empty
    or filled passwords to the `User` header if the latter is
    no supplied yet; it removes the form with empty password.
    If the `User` header already exists the value is ignored
    (or compared to match) but the authentication header is
    removed as always.
  * `map_basic_always=False` does the same, but it also removes
    the form with a filled password (which means that further
    stages will ignore any such password).

### Idea: Tilde maps to User

A popular server-side convention, that unfortunately does not
imply semantics for clients like `User` can, is to begin a URL
path with `/~username`.  This pattern might be recognised as an
alternative to the `User` header.

This might be done with a flag:

  * `map_tilde=False` would map the `/~username` form to a
    `User` header set to `username` and remove the form from
    the path component of the URI.  When the `User` header
    exists, the path component is still removed, but it does
    not have any impact on the `User` header (though it may
    be compared to match).


## Bring Your Own IDentity

We are considering a BYOID mechanism based on Diameter servers
hosted under domain names.  This is not a web-only technology,
so we are not limited to HTTP and can make a choice for a more
dedicated technology.

Diameter is the sequel to RADIUS; its security is better so it
can be used for such realm crossover purposes; indeed, there
are SRV records in DNS for this kind of purpose.  Diameter's
support for bulk interactions and routing of requests and
responses has also improved.  Finally, it is easier to extend
with notions such as SASL fields.

With this in mind, a server receiving a client identity
`john@example.com` can lookup the Diameter server for `example.com`
and relay SASL traffic to the realm.  It does not need any local
credentials to allow for this to work; all it needs to do is use
TLS for trust in the link to the backend Diameter server.


This is not the only way in which we think BYOID can be achieved.
It will me much more powerful once we get our projects for
Kerberos going:
[Impromptu Realm Crossover (KXOVER)](http://realm-xover.arpa2.net/kerberos.html)
and
[TLS-KDH](http://tls-kdh.arpa2.net).
The advantage of these mechanisms is that a crossover relation
is made between realms, not just for individual queries of
individual users.  This makes it extremely efficient for bulk
use, but it will also take longer to get established.  It is
useful though; TLS-KDH authenticates thousands of times faster
than tradition public-key certificates, and it resists
quantum computers; KXOVER currently cannot match that last point,
but will develop in that direction too.
SASL is the short-term solution that can integrate seemlessly
with this same approach.


## ARPA2 Access Control

The ACL setup that we envision is flexible, generic and fast.  More
importantly, it is suitable for realm crossover uses.

We are
[building libraries](https://github.com/arpa2/libarpa2service)
to support the general evaluation of this model, along with
[change subscription](http://steamworks.arpa2.net/pulley.html)
to keep dependents informed.


