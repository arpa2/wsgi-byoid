# setup.py for ARPA2 WSGI Middleware
#
# Package name "arpa2wsgi"
#
# From: Rick van Rein <rick@openfortress.nl>

import setuptools
from os import path

#
# Preparation
#
here = path.dirname (path.realpath (__file__))


#
# Packaging Instructions -- arpa2wsgi
#
readme = open (path.join (here, 'README.MD')).read ()
setuptools.setup (

	# What?
	name = 'arpa2wsgi',
	version = '0.1.0',
	url = 'https://github.com/arpa2/wsgi-middleware',
	description = 'WSGI Middleware for Identity Framework in ARPA2 Projects that implement the InternetWide Architecture',
	long_description = readme,
	long_description_type = 'text/markdown',

	# Who?
	author = 'Rick van Rein (for the ARPA2 Project)',
	author_email = 'rick@openfortress.nl',

	# Where?
	packages = [
		'arpa2wsgi'
	],
	package_dir = {
		'arpa2wsgi': here
	},

	# How?
	# entry_points = ... Not for WSGI, right?

        # Requirements
        install_requires = [ 'json' ],

)

