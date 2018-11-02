
# SASL is intended as a final answer in authentication.
# It has been that answer to all desires in SMTP, IMAP,
# POP3, IRC, LDAP and probably more; there is only one
# protocol that continues to invent its own wheels,
# namely HTTP.  The lack of generic security means that
# web applications fall behind on updates of their
# security, leaving gaping holes in the protection of
# its users.  Many applications implement mediocre
# security levels, and it is precisely those that will
# never change.  The reason is clear: applications
# take another kind of thinking (and perhaps another
# kind of programmer) than security software.
#
# HTTP supports user interaction, and there is no end
# to applications asking the user to enter data, in
# a fashion that could be seen as one-sided automation.
# Other protocols that are less interactive and less
# inventive use extra software to interact with the
# user with normal software, no systems that are
# dynamic and always implemented in a slightly different
# manner.
# 
# Though it is possible to interact with users from
# the web pages exchanged over HTTP,
# this is usually an unsafe environment full of dynamic
# content that comes from a variety of sources.  Many
# pages contain advertisements and are prone to scan as
# much of a user's behaviour as possible.  There is no
# reason why such heterogenic content would stop to
# respect passwords.
#
# Passwords are also the inevitable result of various
# programmers each inventing their own access control
# mechanism.  These programmers tend to specialise in
# application logic, not security.  The result is a
# highly conservative style of security, which sticks
# to old habits that have long considered insecure.
#
# The use of passwords is horrible, and the attempts
# to create web-only single sign-on systems have led
# to slow response times and still a high risk for
# tapping into personal data.
#
# SASL is not a specific authentication mechanism, but
# rather a generic wrapper that captures them all, by
# defining a channeling system through which they can
# all travel.  A gradually evolving set of mechanisms
# have been defined for SASL, and even for passwords
# there are decent mechanisms, though nothing compared
# to a system like Kerberos.  None of these need to
# be forced upon users however; a properly broad SASL
# implementations offers a list of mechanisms from
# which a user chooses.  These settings are not made
# by application software, and they need not be
# inconsistent.
#
# Better even, upgrade SASL to get new mechanisms
# installed.  Not just in websites, but also in
# mail, ldap and all the other applications of SASL.
# There is no need for involvement from any of the
# application programs, as long as they pass on the
# traffic to sufficiently clueful software that also
# follows the upgrade advise.
#
# The web is a dangerous place with fatal attraction.
# We can mitigate most threats by at least treating
# security-sensitive aspects in layers out of reach
# by dangerously dynamic components like JavaScript
# running in an HTML page.  A similar choice would
# be wise for privacy-sensitive aspects.  SASL does
# just that, without the need to bother a programmer
# whose primary interest is his application, not
# the user's online security or privacy.


from __future__ import print_function


import re


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
#TODO# Probably need to get a better quoted-string.
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


# A few simple tests on the complex regular expressions.
#
#TODO# Should be optional, and possibly external to this file.
#
_test = 'SAsL c2s=11bbaa=, s2s=190284ijrjwerowieu987d9fs===, c2c=2kkasjf923y92i3h4, s2c=alskjoeiqwr98237492834=====,mech=\t"TRA LA LALALA", realm\t = \t\t   \t  "dynamo.nep"'
assert (authorization_stx.match (_test) is not None)
assert (auth_param_finder.findall (_test) == [
	('c2s', '11bbaa=', '', '', ''),
	('s2s', '190284ijrjwerowieu987d9fs===', '', '', ''),
	('c2c', '2kkasjf923y92i3h4', '', '', ''),
	('s2c', 'alskjoeiqwr98237492834=====', '', '', ''),
	('', '', '"TRA LA LALALA"', 'TRA LA LALALA', ''),
	('', '', '', '', 'dynamo.nep')])


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
def add_sasl_chal (realm,got_remote=False,hdrval=None):
	hdrval = hdrval + ', ' if hdrval is not None else ''
	mechs = ' '.join (sasl_mechanisms)
	if got_remote and 'EXTERNAL' not in mechs:
		mechs += ' EXTERNAL'
	hdrval += 'SASL realm="' + realm + '", mech="' + mechs + '"'


# Build a SASL response header from its name and the attributes
# that were updated by SASL,starting from those in the request.
# In addition, a base directory of headers is prepared to find
# the new dictionary of response headers.
#
def build_sasl_header (hdrnm, attrs, basedir):
	hdrval = 'SASL'
	comma = ''
	for atnm in ['mech', 'realm', 'name', 'c2c', 's2c', 's2s', 'text']:
		if attrs.has_key (atnm):
			if '2' in atnm:
				hdrval += comma + ' %s=%s' % (atnm, attrs [atnm])
			else:
				hdrval += comma + ' %s="%s"' % (atnm, attrs [atnm])
		comma = ','
	if basedir.has_key (hdrnm):
		# Does this ever occur?  Probably not
		basedir [hdrnm] += ',' + hdrval
	else:
		basedir [hdrnm] = hdrval


class WSGI_SASL (object):

	"""
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

	This class implements WWW authentication.  The
	subclass WSGI_SASL_Proxy overrides a few aspects
	to produce Proxy authentication.
	"""

	status = '401 Unauthorized'
	resp_header = 'WWW-Authenticate'
	req_header = 'Authorization'
	req_envvar = 'HTTP_AUTHORIZATION'

	def __init__ (self, inner_app, realm='secure.realm'):
		"""Instantiate WSGI-SASL as middleware
		   on the path towards the `inner_app`.
		"""
		self.inner_app = inner_app
		self.realm = realm
		self.resp_header_lowcase = self.resp_header.lower ()

	def __call__ (self, outer_env, outer_resp):
		"""This function serves to make the
		   WSGI-SASL instance callable, using the
		   common WSGI pattern.
		"""
		if outer_env.has_key ('HTTP_PROXY_AUTHORIZATION'):
			print ('Processing Proxy-Authorization: header')
			pass #TODO#
		if outer_env.has_key ('HTTP_AUTHORIZATION'):
			print ('Processing Authorization: header')
			pass #TODO#
		#
		# Process Proxy-Authorization: or Authorization: headers.
		result = None
		if environ.has_key (req_envvar):
			print ('Processing [Proxy-]Authorization: header')
			pass #TODO#
		if result is not None:
			return result
		#
		# Forward the call to the inner application
		inner_env = outer_env
		got_remote = outer_env.has_key ('REMOTE_USER')
		inner_resp = self._curried_inner_resp (outer_env, outer_resp, got_remote)
		self.inner_app (inner_env, inner_resp)

	def _curried_inner_resp (self, outer_env, outer_resp, got_remote):
		"""This function is called to produce an
		   inner start_response function, building
		   on the information for the outer and
		   maintaining state on things like SASL
		   negotiation progress.
		"""
		#
		def parse_header (hdrval):
			bad = False
			#
			# First ensure overal syntax; this makes sure that our
			# upcoming iteration works as expected.
			if not authorization_stx.match (hdrval):
				bad = True
			#
			# Continue to parse the structure and check even more
			attrs = { }
			for (x2y,data,_,mech,realm) in auth_param_finder.findall (hdrval):
				x2y = x2y.lower ()
				if x2y != '':
					bad = bad or attrs.has_key (x2y)
					attrs [x2y] = data
				elif mech != '':
					bad = bad or attrs.has_key ('mech')
					attrs ['mech'] = mech
				elif realm != '':
					bad = bad or attrs.has_key ('realm')
					attrs ['realm'] = realm
			bad = bad or not attrs.has_key ('c2s')
			#
			# Return an error if there was a problem with the syntax
			if bad:
				start_response ('403 Forbidden', { 'Content-Type', 'text/plain' })
				return ['Unrecognised %s: header' % self.resp_header]
			#TODO# Process and enjoy; pass or return when decided
			sasl_status = '200 OK'
			if need_to_continue_sasl:
				resphdr = build_sasl_header (self.resp_header, attrs, { 'Content-Type': 'text/plain' })
				start_response (sasl_status or self.status, resphdr)
				return ['Please continue the SASL exchange']
			return None
		#
		def inner_resp (status, inner_resphdr):
			print ('Response status', status)
			print ('Response headers', inner_resphdr)
			if status [:3] != self.status [:3]:
				return outer_resp (status, inner_resphdr)
			#
			hdrset = False
			outer_resphdr = [ ]
			for (name,hval) in inner_resphdr:
				if name.lower () == self.resp_header_lowcase:
					hval = add_sasl_chal (self.realm, got_remote, value)
					hdrset = True
				outer_resphdr.append ( (name,hval) )
			if not hdrset:
				outer_resphdr.append ( (self.resp_header,add_sasl_chal (realm, got_remote) ) )
			#
			return outer_resp (status, outer_resphdr)
		#
		# Return the inner function, bound to our context
		return inner_resp


class WSGI_SASL_Proxy (WSGI_SASL):

	"""This object handles Proxy authentication over WSIG-SASL.
	   It usually comes before the handler for WWW authentication,
	   because Proxy authentication is more local, as in per-leg,
	   than WWW authentication.  Other than a few settings, this
	   class does not override the logic of plain WWW as defined
	   in the WSGI_SASL superclass.
	"""

	status = '407 Proxy Authentication Requires'
	resp_header = 'Proxy-Authenticate'
	req_header = 'Proxy-Authorization'
	req_envvar = 'HTTP_PROXY_AUTHORIZATION'

