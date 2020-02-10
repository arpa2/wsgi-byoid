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


# Curried response code to add "Vary: User" to the response.
#
def _curried_add_vary (outer_resp):
	def _add_vary (status, resphdrs):
		resphdrs.append ( ('Vary','User') )
		outer_resp (status, resphdrs)
	return _add_vary


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

	def __init__ (self, inner_app, user_syntax=None, allow_empty=True):
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

	def __call__ (self, outer_env, outer_resp):
		"""This function makes WSGI-User instances
		   callable, using the common WSGI pattern.
		"""
		#
		# Parse the User header
		user = outer_env.get ('HTTP_USER')
		local_user = None
		if user is None:
			# No header found
			pass
		elif user == '':
			if self.allow_empty:
				# Accept empty value of User header
				local_user = ''
		elif ':' in user:
			# Do not accept colons in User
			pass
		else:
			local_user = urllib.parse.unquote (user)
			if not self.user_syntax.match (local_user):
				# Syntax wrong -- ignore User header
				local_user = None
		# 
		# Decide on impact of the header
		inner_env = outer_env
		inner_resp = outer_resp
		if local_user is not None:
			inner_env ['LOCAL_USER'] = local_user
			inner_resp = _curried_add_vary (outer_resp)
		return self.inner_app (inner_env, inner_resp)

