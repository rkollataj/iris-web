#  IRIS Source Code
#  contact@dfir-iris.org
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

# OIDC Configuration
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.oic.message import RegistrationResponse
from oic.oic.message import ProviderConfigurationResponse


def _apply_oidc_ssl_policy(client: Client, app):
    skip_ssl_verify = app.config.get("OIDC_SKIP_SSL_VERIFY", False)
    if not skip_ssl_verify:
        return {}

    app.logger.warning("OIDC_SKIP_SSL_VERIFY is enabled. TLS certificate verification is disabled for OIDC requests.")

    # pyoidc can use either settings-level verify flag or request_args.
    if hasattr(client, "settings") and hasattr(client.settings, "verify_ssl"):
        client.settings.verify_ssl = False
    if hasattr(client, "request_args") and isinstance(client.request_args, dict):
        client.request_args["verify"] = False

    return {"verify": False}


def get_oidc_client(app) -> Client:
    client = Client(client_authn_method=CLIENT_AUTHN_METHOD)
    request_kwargs = _apply_oidc_ssl_policy(client, app)

    # retrieve provider configuration dynamically from metadata
    # or fall back to env vars
    try:
        client.provider_config(app.config.get("OIDC_ISSUER_URL"), **request_kwargs)
    except TypeError:
        # Older pyoidc versions may not accept kwargs here. The settings/request_args
        # from _apply_oidc_ssl_policy still apply for outgoing HTTP requests.
        client.provider_config(app.config.get("OIDC_ISSUER_URL"))
    except Exception as e:
        app.logger.warning(f"Could not read OIDC metadata, using environment variables - error {e}")
        op_info = ProviderConfigurationResponse(
            issuer=app.config.get("OIDC_ISSUER_URL"),
            authorization_endpoint=app.config.get("OIDC_AUTH_ENDPOINT"),
            token_endpoint=app.config.get("OIDC_TOKEN_ENDPOINT"),
            end_session_endpoint=app.config.get("OIDC_END_SESSION_ENDPOINT"),
        )

        client.handle_provider_config(op_info, op_info['issuer'])

    info = {
        "client_id": app.config.get("OIDC_CLIENT_ID"),
        "client_secret": app.config.get("OIDC_CLIENT_SECRET")
    }
    client_reg = RegistrationResponse(**info)
    client.store_registration_info(client_reg)

    return client
