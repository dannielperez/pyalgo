"""pyalgo — small Python helpers for Algo SIP endpoints (speakers, horns, paging)."""

from .client import AlgoClient, AlgoDevice, AlgoError, AlgoAuthError, identify
from .rest import (
    AlgoRestClient,
    AlgoRestError,
    hmac_authorization,
    basic_auth_header,
    SIP_SERVER_PRIMARY,
    SIP_SERVER_SECONDARY,
    SIP_AUTH_ID,
    SIP_AUTH_PASSWORD,
    SIP_EXTENSION,
    SIP_PROXY_ADDRESS,
    SIP_PROXY_PORT,
)
from .status import ALGO_OUI, AlgoStatus, SipRegistration, parse_sip_registration, parse_status

__all__ = [
    # LuCI web client (login, status, enable-REST)
    "AlgoClient",
    "AlgoDevice",
    "AlgoError",
    "AlgoAuthError",
    "identify",
    # Official RESTful API client
    "AlgoRestClient",
    "AlgoRestError",
    "hmac_authorization",
    "basic_auth_header",
    "SIP_SERVER_PRIMARY",
    "SIP_SERVER_SECONDARY",
    "SIP_AUTH_ID",
    "SIP_AUTH_PASSWORD",
    "SIP_EXTENSION",
    "SIP_PROXY_ADDRESS",
    "SIP_PROXY_PORT",
    # status parsers
    "AlgoStatus",
    "SipRegistration",
    "parse_sip_registration",
    "parse_status",
    "ALGO_OUI",
]
