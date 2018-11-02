# README for WSGI-SASL

> *WSGI allows stacks of HTTP-processing layers to
> form a service.  SASL is a generic authentication
> layer that can improve the security of HTTP applications.
> WSGI-SASL is implements SASL-processing > in a WSGI stack.*

WSGI-SASL middleware filters HTTP traffic before
it reaches an application that may want to use a
`REMOTE_USER` header.  The application will raise
401 or 407 if it lacks one, thereby triggering the
SASL exchange that it may or may not know about.

The client may provide credentials, either
pro-actively or reminiscent of a foregoing
SASL interaction.  When these lead to the
establishment of a `REMOTE_USER`.

When a `REMOTE_USER` already exists, it is
acceptable to the `SASL EXTERNAL` method.
By default it is actually passed through.
When SASL is tried in spite of this value,
it is assumed that different negotiation
is required to replace `REMOTE_USER`, or to
at least give the client such an opportunity.

This layer allows other mechanisms to be setup
in preceding or follow-up layers:

  * It passes `REMOTE_USER` trough; the preceding
    stack can be incorporated as `SASL EXTERNAL`
    so be mindful that it is sufficiently
    secure for the application's purposes;

  * It passes `Authorize` headers that reference
    another security protocol;

  * It externds to a list of challenges in a
    401 or 407 Initial Response or, if the list
    has not been started yet, it starts it.

  * It passes 200 and 403 Final Responses, along
    with all the other status codes to which
    HTTP-SASL has nothing to add.


This is the `wsgisasl.py` module:

```python
# WSGI-SASL module; possibly insert HTTP SASL authentication
# into a WSGI flow.
#
# From: Rick van Rein <rick@openfortress.nl>


import re


# For now, until we connect as middleware should
#
import some_very_nice_wsgi_app as inner_application


# Regular expressions to match against request headers
#
# From RFC 7325:
#
#    credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
#   
#    auth-scheme = token
#                  -- this token is case-insensitive
#
#    auth-param  = token BWS "=" BWS ( token / quoted-string )
#                  -- this token is case-insensitive
#                  -- we always use the quoted-string form
#   
#    token68     = 1*( ALPHA / DIGIT /
#                  "-" / "." / "_" / "~" / "+" / "/" ) *"="
#
# BWS references *( SP / HTAB ) and then there is
#
#    quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
#    qdtext         = HTAB / SP /%x21 / %x23-5B / %x5D-7E / obs-text
#    obs-text       = %x80-FF
#    quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
#
# Our syntax is more constrained, allowing space-separated
# GSS-API mechanism names, which we can formalise as
#
#    mech-string = DQUOTE mech-name *( SP sasl-mech ) DQUOTE
#
# The sasl-mech is defined in RFC 4422 as:
#
#    sasl-mech    = 1*20mech-char
#    mech-char    = UPPER-ALPHA / DIGIT / HYPHEN / UNDERSCORE
#    ; mech-char is restricted to A-Z (uppercase only), 0-9, -, and _
#    ; from ASCII character set.
#
#    UPPER-ALPHA  = %x41-5A  ; A-Z (uppercase only)
#    DIGIT        = %x30-39  ; 0-9
#    HYPHEN       = %x2D ; hyphen (-)
#    UNDERSCORE   = %x5F ; underscore (_)
#
# The following scheme finds pairs of matched parameters.
# Both the quoted string and token68 forms are not unpacked.
#

re_sasl_mech = '(?:[A-Z0-9-_]{1,20})'
re_mechstring = '(?:["](' + re_sasl_mech + '(?:[ ]' + re_sasl_mech + ')*)["])'

re_dnsstring = '(?:"(' + '[a-zA-Z0-9-_]+(?:\.[a-zA-Z0-9-_]+)+' + ')")'

re_bws = re_ows = '(?:[ \\t]*)'
re_token68 = '(?:[a-zA-Z0-9-._~+/]+[=]*)'
re_auth_param = ( '(?:' + '([CcSs][2][CcSs])' + re_bws + '[=]' + re_bws + '(' + re_token68 + ')' +
	'|' + '[Mm][Ee][Cc][Hh]' + re_bws + '[=]' + re_bws + '(' + re_mechstring + ')' +
	'|' + '[Rr][Ee][Aa][Ll][Mm]' + re_bws + '[=]' + re_bws + '' + re_dnsstring + ')' )
re_auth_scheme = '[Ss][Aa][Ss][Ll]'
re_credentials = '(?:' + re_auth_scheme + '(?:[ ]+' + re_auth_param + '(?:' + re_ows + '[,]' + re_ows + re_auth_param + ')+)?)'

re_credentials = '(?:' + re_auth_scheme + '(?:[ ]+(' + re_auth_param + ')(?:' + re_ows + '[,]' + re_ows + re_auth_param + ')+)?)'

# We use authorization_stx to check the syntax of Authorization: and
# Proxy-Authorization: headers, and auth_param_finder to findall()
#
authorization_stx = re.compile ('^' + re_credentials + '$')
auth_param_finder = re.compile (re_auth_param)


test = 'SAsL c2s=11bbaa=, s2s=190284ijrjwerowieu987d9fs===, c2c=2kkasjf923y92i3h4, s2c=alskjoeiqwr98237492834=====,mech=\t"TRA LA LALALA", realm\t = \t\t   \t  "dynamo.nep"'
assert (authorization_stx.match (test) is not None)
assert (auth_param_finder.findall (test) == [
	('c2s', '11bbaa=', '', '', ''),
	('s2s', '190284ijrjwerowieu987d9fs===', '', '', ''),
	('c2c', '2kkasjf923y92i3h4', '', '', ''),
	('s2c', 'alskjoeiqwr98237492834=====', '', '', ''),
	('', '', '"TRA LA LALALA"', 'TRA LA LALALA', ''),
	('', '', '', '', 'dynamo.nep')])


# Map a status header 401 and/or 407 to (realm,lowercaseheader,camelcapsheader)
#
#TODO# Perhaps make two classes for two uses; rediculous to keep this floating
#
status2hdr = {
	'401': ( 'ARPA2 BYOID (via SASL)',  'www-authenticate',   'WWW-Authenticate'),
	'407': ( 'ARPA2 BYOID (via SASL)','proxy-authenticate', 'Proxy-Authenticate')
}

# The sasl_mechanisms provided
#TODO# Derive from SASL stack
#
sasl_mechanisms = [ 'GSSAPI', 'PLAIN', 'CRAM-MD5', 'DIGEST-MD5', 'SCRAM-SHA1' ]


# Extend the content of a server-sent 401 or 407 header
# WWW-Authenticate or Proxy-Authenticate with options
# to authenticate with SASL.  If the header does not
# yet exist, add it to make the inner WSGI layer conform
# to the HTTP specification.
#
def add_sasl_options (realm,hdrval=None):
	hdrval = hdrval + ', ' if hdrval is not None else ''
	mechs = ' '.join (sasl_mechanisms)
	#TODO# Based on REMOTE_USER, we might add the EXTERNAL mechanism
	hdrval += 'SASL realm="' + realm + '", "' + mechs + '"'


# Take a step in SASL processing.  The mode is
# one of 'proxy' or 'www'.
#
#TODO# Probably need evolving state (inner fun).
#
def step_sasl_generator (start_response, mode='www'):

	ctx = TODO_sasl_context ()

	mech = None

	def step_sasl (hdrval):
		if not authorization_stx.match (hdrval):
			start_response ('403 Forbidden', { 'Content-Type', 'text/plain' })
			return ['Unrecognised [Proxy-]Authorization: header']
		attrs = { }
		for (x2y,data,_,mech,realm) in auth_param_finder.findall (hdrval):
			x2y = x2y.lower ()
			if x2y != '':
				attrs [x2y] = data
			elif mech != '':
				attr ['mech'] = mech
			elif realm != '':
				attr ['realm'] = realm
		#TODO# Process and enjoy; pass or return when decided
		return None

	return step_sasl


# The WSGI application overrides the start_response call
# with one that optionally inserts SASL options.  Then it
# processes the request to learn if it triggers SASL.
#
def application (environ, start_outer_response):

	pass_response = False

	def start_inner_response (status, inner_headers):
		if status [:3] not in status2hdr.keys ():
			pass_response = True
			start_response (status, inner_resphdr)
			return
		(realm,lowcasehdr,camcapshdr) = status2hdr [status [:3]]
		#TODO# Is it worthwhile making this iterable?  Probably not.
		#TODO# We could push a tomerge_saslauthopt through foldr() though.
		hdrval = None
		outer_resphdr = [
			(name,(hdrval = add_sasl_options (realm,value)
			       if name.lower () == lowcasehdr
                               else value))
			for (name,value) in inner_resphdr ]
		if hdrval is None:
			outer_resphdr = [ (camcapshdr, add_sasl_options (realm)) ] + outer_resphdr
		start_response (status, outer_resphdr)

	#
	# Process Proxy-Authorization: or Authorization: headers
	# Note that Proxy-Authorization headers take precedence;
	# they are local and so at least these must be for us.
	# In practice, there should be no competition.
	result = None
	if environ.has_key ('HTTP_PROXY_AUTHORIZATION'):
		print ('Processing Proxy-Authorization: header')
		pass #TODO#
	elif environ.has_key ('HTTP_AUTHORIZATION'):
		print ('Processing Authorization: header')
		pass #TODO#
	if result is not None:
		return result
	#
	# Prepare for calling the inner application
	inner_environ = environ
	if environ.has_key ('REMOTE_USER'):
		pass #TODO# Note the presence of REMOTE_USER for 401/407 processing
	return inner_application (outer_environ, start_innert_response)
```


