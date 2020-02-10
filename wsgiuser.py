# The User: header from draft-vanrein-http-noauth-user
#
# This header extends the resource space of HTTP with a user name.
# This can be used on top of the host name to decide about the
# name space to address.  The use of this header is that it adds
# common semantics for user names, unlike local /~user conventions
# and its many variations.  Semantics are helpful for automation
# of the interactions with sites.
#
# Note that the User: header defines a user on the server-side,
# which makes it different from authentication users that represent
# a client identity.  Yes, they may happen to be the same if the
# resource is owned by the client with a matching identity, but that
# is just the simplest way of matching these two user concepts.
# Supporting only that is comparable to an email server that only
# supports sending emails to yourself.  The most general notion is
# an Access Control List that decides if an authenticated client
# identity may access a (user) resource on the HTTP server.  This
# line of thinking also opens up authentication for realm crossover,
# which is technology that enables users to Bring Your Own IDentity.
#
# From: Rick van Rein <rick@openfortress.nl>


import re
import base64
import urllib.parse

# The default identity pattern is an empty string =or= a NAI.
# The NAI syntax is defined in Section 2.1 of RFC 7542.
# Use re_nai for the plain NAI.
#
def _chrs (fst,lst):
	return '[\\x%02x-\\x%02x]' % (fst,lst)
rex_tail = _chrs(0x80,0xbf)
rex_utf8_2 = _chrs(0xc2,0xdf) + rex_tail
rex_utf8_3 = '(?:%s|%s|%s|%s)' % (
		_chrs(0xe0,0xe0) + _chrs(0xa0,0xbf) + rex_tail,
		_chrs(0xe1,0xec) + rex_tail         + rex_tail,
		_chrs(0xed,0xed) + _chrs(0x80,0x9f) + rex_tail,
		_chrs(0xee,0xef) + rex_tail         + rex_tail )
rex_utf8_4 = '(?:%s|%s|%s)' % (
		_chrs(0xf0,0xf0) + _chrs(0x90,0xbf) + rex_tail + rex_tail,
		_chrs(0xf1,0xf3) + rex_tail         + rex_tail + rex_tail,
		_chrs(0xf4,0xf4) + _chrs(0x80,0x8f) + rex_tail + rex_tail )
rex_utf8_xtra_char = '(?%s|%s|%s)' % (rex_utf8_2, rex_utf8_3, rex_utf8_4)
rex_char = '[\x80-\xff]'
#TODO# & ' * / = ? ^ _ ` { | } ~ inside [...]
#TODO# rex_string = '(?:(?:[a-zA-Z0-9!#$%+-]|%s)+)' % rex_utf8_xtra_char
#TODO# rex_string = '(?:(?:[a-zA-Z0-9]|%s)+)' % rex_utf8_xtra_char
rex_string = '(?:(?:[a-zA-Z0-9]|%s)+)' % rex_char
rex_username = '(?:%s(?:[.]%s)*)' % (rex_string, rex_string)
#TODO# rex_utf8_rtext = '(?:[a-zA-Z0-9]|%s)' % rex_utf8_xtra_char
rex_utf8_rtext = '(?:[a-zA-Z0-9]|%s)' % rex_char
rex_ldh_str = '(?:(?:%s|[-])*%s)' % (rex_utf8_rtext, rex_utf8_rtext)
rex_label = '(?:%s(?:%s)*)' % (rex_utf8_rtext, rex_ldh_str)
rex_realm = '(?:%s(?:[.]%s)+)' % (rex_label, rex_label)
rex_nai = '(?:%s(?:[@]%s)?|[@]%s)' % (rex_username, rex_realm, rex_realm)
#DEBUG# print ('rex_nai = %r' % rex_nai)
re_nai = re.compile ('^%s$' % rex_nai)


# Regular expression before percent unescaping
#


# Regular expression for the tilde form in PATH_INFO
#
rex_tilde = '^/~([^/]*)(/.*|$)'
re_tilde = re.compile (rex_tilde)


# Curried response code to add "Vary: User" to the response.
#
def _curried_add_vary (outer_resp):
	def _add_vary (status, resphdrs):
		outer_resp (status, resphdrs)
		resphdrs.append ( ('Vary','User') )
	return _add_vary


# Error responder to indicate that user names did not match
#
def mismatch_app (environ, start_response):
	status = '400 Bad Request'
	response_headers = [('Content-Type', 'text/plain')]
	start_response (status, response_headers)
	return ['You provided several server-side user resource that did not match:\n - User header as per draft-vanrein-http-unauth-user\n - Basic authentication user name\n - Path information format /~username\nPlease check that these match or talk to your server administrator\n']


class WSGI_User (object):

	"""WSGI-User middleware filters HTTP traffic
	   to detect if the User header is present.
	   If it is, the escape-removed version of
	   the header is syntax checked and, when
	   accepted, the result is stored in the
	   LOCAL_USER environment variable.
	   
	   The syntax check defaults to the NAI, as
	   defined in RFC 7542, with an extra flag
	   to also permit empty strings, defaulting
	   to True.
	   
	   When a LOCAL_USER value is delivered, the
	   cache will be notified of possible influence
	   of the User header through Vary in the
	   response.
	"""

	def __init__ (self, inner_app, user_syntax=None, allow_empty=True,
			map_tilde=True, map_basic=True, map_basic_always=False,
			proxy_auth=False):
		"""Instantiate WSGI-User middleware for
		   the given syntax for LOCAL_USER, where
		   the default is the NAI syntax.  Other
		   regexes can be supplied.  The additional
		   flag allow_empty stores empty values for
		   the User header in LOCAL_USER even when
		   the syntax does not accept it, as would
		   be the case with a NAI.  By default,
		   empty strings are allowed.  Note that
		   the User header may contain % escapes,
		   which are removed before any of this
		   processing takes place.  Also note
		   that URIs, which are one possible
		   source for the User header value, are
		   not constrained to UTF-8 but can send
		   general binary strings (which is why
		   the addition of a parser is healthy).
		"""
		if user_syntax is None:
			user_syntax = re_nai
		elif type (user_syntax) == str:
			user_syntax = re.compile (user_syntax)
		self.user_syntax = user_syntax
		self.allow_empty = allow_empty
		self.inner_app   = inner_app
		self.map_tilde   = map_tilde
		self.map_basic   = map_basic or map_basic_always
		self.drop_passwd = map_basic_always
		self.basic_header = ( 'HTTP_PROXY_AUTHORIZATION'
		                      if proxy_auth else
		                      'HTTP_AUTHORIZATION' )

	def __call__ (self, outer_env, outer_resp):
		"""This function makes WSGI-User instances
		   callable, using the common WSGI pattern.
		"""
		mismatch = False
		inner_env = outer_env
		inner_resp = outer_resp
		#
		# Parse the User header
		user = outer_env.get ('HTTP_USER')
		local_user = None
		if user is None:
			# No header found
			pass
		elif ':' in user:
			# Do not accept colons in User
			pass
		else:
			#TODO# Insufficient % escape syntax checking?
			local_user = urllib.parse.unquote (user)
			inner_resp = _curried_add_vary (outer_resp)
		#
		# Possibly map /~user path information
		if self.map_tilde:
			tm = re_tilde.match (outer_env ['PATH_INFO'])
			if tm is not None:
				(tilde_user,new_path) = tm.groups ()
				if new_path == '':
					new_path = '/'
				inner_env ['PATH_INFO'] = new_path
				if local_user is not None:
					mismatch = local_user != tilde_user
				if self.user_syntax.match (tilde_user):
					local_user = tilde_user
		#
		# Possibly map Basic auhentication to a User header
		if self.map_basic and self.basic_header in outer_env:
			try:
				basic = outer_env [self.basic_header]
				assert basic [:6] == 'Basic '
				resp = base64.b64decode (basic [6:])
				resp = str (resp, 'utf-8')
				#DEBUG# print ('Basic sent %r' % resp)
				(basic_user,pwd) = resp.split (':', 1)
				if local_user is not None:
					mismatch = local_user != basic_user
				local_user = basic_user
				#DEBUG# print ('Password is %r' % pwd)
				if self.drop_passwd or pwd == '':
					del inner_env [self.basic_header]
			except Exception as e:
				#DEBUG# print ('Exception: %r' % e)
				pass
		#
		# Check if the local_user syntax is acceptable
		#DEBUG# print ('local_user = %r' % local_user)
		if local_user is None:
			# No local user defined
			pass
		elif local_user == '':
			# Empty string -- maybe ignore User header
			if not self.allow_empty:
				local_user = None
		elif not self.user_syntax.match (local_user):
			# Syntax wrong -- ignore User header
			local_user = None
		#
		# Possibly retract the cache hint Vary: User
		if local_user is None:
			# No local user -- no cache hint
			inner_resp = outer_resp
		# 
		# Decide on impact of the header
		next_app = self.mismatch_app if mismatch else self.inner_app
		if local_user is not None:
			inner_env ['LOCAL_USER'] = local_user
		return next_app (inner_env, inner_resp)

