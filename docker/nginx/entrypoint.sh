#!/usr/bin/env bash

#  IRIS Source Code
#  Copyright (C) 2021 - Airbus CyberSecurity (SAS)
#  ir@cyberactionlab.net
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 3 of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#  Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
#  Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

set -e

HTTP_LISTEN_DIRECTIVE=""
HTTPS_LISTEN_DIRECTIVE=""
SSL_CONFIG_BLOCK=""

if [ -n "${INTERFACE_HTTP_PORT:-}" ]; then
  HTTP_LISTEN_DIRECTIVE="listen          ${INTERFACE_HTTP_PORT};"
fi

if [ -n "${INTERFACE_HTTPS_PORT:-}" ]; then
  if [ -z "${CERT_FILENAME:-}" ] || [ -z "${KEY_FILENAME:-}" ]; then
    echo "INTERFACE_HTTPS_PORT is set but CERT_FILENAME or KEY_FILENAME is missing" >&2
    exit 1
  fi
  HTTPS_LISTEN_DIRECTIVE="listen          ${INTERFACE_HTTPS_PORT} ssl;"
  SSL_CONFIG_BLOCK="    # SSL CONF, STRONG CIPHERS ONLY
    ssl_protocols               TLSv1.2 TLSv1.3;

    ssl_prefer_server_ciphers   on;
    ssl_certificate             /www/certs/${CERT_FILENAME};
    ssl_certificate_key         /www/certs/${KEY_FILENAME};
    ssl_ecdh_curve              secp521r1:secp384r1:prime256v1;
    ssl_buffer_size             4k;

    # DISABLE SSL SESSION CACHE
    ssl_session_tickets         off;
    ssl_session_cache           none;"
fi

if [ -z "${HTTP_LISTEN_DIRECTIVE}" ] && [ -z "${HTTPS_LISTEN_DIRECTIVE}" ]; then
  echo "No interface port set. Set INTERFACE_HTTP_PORT and/or INTERFACE_HTTPS_PORT." >&2
  exit 1
fi

export HTTP_LISTEN_DIRECTIVE HTTPS_LISTEN_DIRECTIVE SSL_CONFIG_BLOCK

# envsubst will make a substitution on every $variable in a file, since the nginx file contains nginx variable like $host, we have to limit the substitution to this set
# otherwise, each nginx variable will be replaced by an empty string
envsubst '${HTTP_LISTEN_DIRECTIVE} ${HTTPS_LISTEN_DIRECTIVE} ${SSL_CONFIG_BLOCK} ${IRIS_UPSTREAM_SERVER} ${IRIS_UPSTREAM_PORT} ${SERVER_NAME} ${KEY_FILENAME} ${CERT_FILENAME} ${IRIS_BASE_PATH}' < /etc/nginx/nginx.conf > /tmp/nginx.conf
cp /tmp/nginx.conf /etc/nginx/nginx.conf
rm /tmp/nginx.conf

exec nginx -g "daemon off;"
