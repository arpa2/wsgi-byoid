#!/usr/bin/env python3
#
# Test WSGI middleware, based on fragments in the Feb 10, 2020 content of
# https://en.wikipedia.org/wiki/Web_Server_Gateway_Interface
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import json
from io import BytesIO


# A simple WSGI terminator that dumps the environment as a JSON dictionary
#
def wsgi_env2json (environ, start_response):
	#DEBUG# print ('wsgi_env2json starts')
	start_response ('200 OK', [('Content-Type', 'application/json; charset=utf-8')])
	#DEBUG# print ('wsgi_env2json responded')
	yield bytes (json.dumps (environ), 'utf-8')
	#DEBUG# print ('wsgi_env2json finished')


# The actual test routine will make a call and analyse the results
#  - test_name is printed before errors, and in the final result
#  - app is the generator under the WSGI protocol conventions
#  - envin  is a dict with request  headers and other environment variables
#  - envout is a dict with response headers
#  - jsonin  is an optional dict to send as  JSON request  body [TODO:UNIMPL]
#  - jsonout is an optional dict to test the JSON response body
#
def testwsgi (test_name, app, envin, envout={}, jsonin=None, jsonout=None):
	status = None
	headers = None
	body = BytesIO()
	ok = True

	# Capture the response start
	def start_response (rstatus, rheaders):
		#DEBUG# print ('Response test %s' % (test_name,))
		nonlocal status, headers
		status, headers = rstatus, rheaders

	# Invoke the app to be tested
	#DEBUG# print ('Starting test %s' % (test_name,))
	app_iter = app (envin, start_response)
	#DEBUG# print ('Returned test %s' % (test_name,))

	# Retrieve the body (to start the generator)
	for data in app_iter:
		#DEBUG# print ('Passing through data')
		if status is None or headers is None:
			sys.stderr.write ('%s: Late call to start_response()\n' % (test_name,))
		body.write(data)
	if hasattr(app_iter, 'close'):
		app_iter.close()

	# Check that the response status is "200 OK"
	if status != '200 OK':
		sys.stderr.write ('%s: Response status is %s\n' % (test_name, status))
		ok = False

	# Check that response header values match envout
	#DEBUG# print ('Headers: %r' % headers)
	for (hdr,val) in headers:
		if hdr in envout:
			if envout [hdr] == val:
				del envout [hdr]
			else:
				sys.stderr.write ('%s: Header %s got %s, expected %s\n' % (test_name, hdr,val,envout [hdr]))
				ok = False

	# Check that no headers in envout are missing in the response
	for (hdr,val) in envout.items ():
		if val is not None:
			sys.stderr.write ('%s: Missing response header %s: %s\n' % (test_name ,hdr, val))
			ok = False

	# Check the body (if so desired)
	if jsonout is not None:
		bodygot = json.loads (str (body.getvalue (), 'utf-8'))
		if jsonout != bodygot:
			sys.stderr.write ('%s: Body is %s, body expected was %s\n' % (test_name, bodygot,jsonout))
	
	# Did the test succeed?
	result = 'SUCCESS' if ok else 'FAILURE'
	print ('%s on test %s' % (result,test_name))
	return ok


# Check the test code itself with no test in between
#
envin = {
	"TEST": "Home Game" }
envout = { }
jsonout = {
	"TEST": "Home Game" }
assert (testwsgi ('test_self', wsgi_env2json, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with "User: john"
#
envin = {
	"HTTP_USER": "john" }
envout = {
	"Vary": "User" }
jsonout = {
	"HTTP_USER": "john",
	"LOCAL_USER": "john" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json)
assert (testwsgi ('user_john', wu, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with empty User header (accepting it)
#
envin = {
	"HTTP_USER": "" }
envout = {
	"Vary": "User" }
jsonout = {
	"HTTP_USER": "",
	"LOCAL_USER": "" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json, allow_empty=True)
assert (testwsgi ('user_empty_accept', wu, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with empty User header (rejecting it)
#
envin = {
	"HTTP_USER": "" }
envout = {
	"Vary": None }
jsonout = {
	"HTTP_USER": "" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json, allow_empty=False)
assert (testwsgi ('user_empty_reject', wu, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with "User: jøhn" (UTF-8 for ø is %c3%b8)
#
envin = {
	"HTTP_USER": "j%c3%b8hn" }
envout = {
	"Vary": "User" }
jsonout = {
	"HTTP_USER": "j%c3%b8hn",
	"LOCAL_USER": "jøhn" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json)
assert (testwsgi ('user_jøhn_percentescape', wu, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with a User that has an error is % escaping
#
envin = {
	"HTTP_USER": "j%c%3b8hn" }
envout = {
	"Vary": None }
jsonout = {
	"HTTP_USER": "j%c%3b8hn" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json)
assert (testwsgi ('user_jøhn_errorescape', wu, envin, envout, jsonout=jsonout))


# Check the wsgiuser tool with a non-UTF-8 escape code %c3%b8%b8
#  -> envout explicitly refuses the "Vary" header with value set to None
#  -> jsonout is complete, and does not list LOCAL_USER
#
envin = {
	"HTTP_USER": "j%c3%b8%b8hn" }
envout = {
	"Vary": None }
jsonout = {
	"HTTP_USER": "j%c3%b8%b8hn" }
import wsgiuser
wu = wsgiuser.WSGI_User (wsgi_env2json)
assert (testwsgi ('user_j%c3%b8%b8hn_utf8failure', wu, envin, envout, jsonout=jsonout))



