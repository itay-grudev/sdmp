# Software License Agreement (BSD License)
#
# Copyright (c) 2008-2011, WIDE Project and NICT
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
# * Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# * Neither the name of the WIDE Project or NICT nor the
#   names of its contributors may be used to endorse or
#   promote products derived from this software without
#   specific prior written permission of WIDE Project and
#   NICT.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
# TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# - Find gnutls
# Find the native GNUTLS includes and library
#
#  GNUTLS_FOUND - True if gnutls found.
#  GNUTLS_INCLUDE_DIR - where to find gnutls.h, etc.
#  GNUTLS_LIBRARIES - List of libraries when using gnutls.
#  GNUTLS_VERSION_210 - true if GnuTLS version is >= 2.10.0 (does not require additional separate gcrypt initialization)
#  GNUTLS_VERSION_212 - true if GnuTLS version is >= 2.12.0 (supports gnutls_transport_set_vec_push_function)
#  GNUTLS_VERSION_300 - true if GnuTLS version is >= 3.00.0 (x509 verification functions changed)
#  GNUTLS_VERSION_310 - true if GnuTLS version is >= 3.01.0 (stabilization branch with new APIs)

if (GNUTLS_INCLUDE_DIR AND GNUTLS_LIBRARIES)
  set(GNUTLS_FIND_QUIETLY TRUE)
endif (GNUTLS_INCLUDE_DIR AND GNUTLS_LIBRARIES)

# Include dir
find_path(GNUTLS_INCLUDE_DIR
	NAMES
	  gnutls.h
	  gnutls/gnutls.h
)

# Library
find_library(GNUTLS_LIBRARY
  NAMES gnutls
)

# handle the QUIETLY and REQUIRED arguments and set GNUTLS_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GNUTLS DEFAULT_MSG GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR)

IF(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES ${GNUTLS_LIBRARY} )
ELSE(GNUTLS_FOUND)
  SET( GNUTLS_LIBRARIES )
ENDIF(GNUTLS_FOUND)

# Lastly make it so that the GNUTLS_LIBRARY and GNUTLS_INCLUDE_DIR variables
# only show up under the advanced options in the gui cmake applications.
MARK_AS_ADVANCED( GNUTLS_LIBRARY GNUTLS_INCLUDE_DIR )
