import datetime as dt
import typing as t

from pydantic import Extra, Field, AnyHttpUrl, constr

from kube_custom_resource import CustomResource, schema

from ...config import settings


class ClientRegistrationTokenSpec(schema.BaseModel):
    """
    The spec for a client registration token.
    """
    realm_name: constr(regex = r"[a-z0-9-]+") = Field(
        ...,
        description = "The name of the realm in which the token should be made."
    )
    token_secret_name: constr(regex = r"[a-z0-9-]+") = Field(
        ...,
        description = "The name of the secret in which the token should be placed."
    )
    token_secret_key: constr(min_length = 1) = Field(
        "client-registration-token",
        description = "The key of the token within the named secret."
    )
    token_expiration: schema.conint(gt = 0) = Field(
        settings.keycloak.token_default_expiration,
        description = "The expiry of the token from when it is created, in seconds."
    )
    token_client_count: schema.conint(gt = 0) = Field(
        settings.keycloak.token_default_client_count,
        description = "The number of clients that the token is permitted to create."
    )


class ClientRegistrationTokenPhase(str, schema.Enum):
    """
    The possible phases for a client registration token.
    """
    UNKNOWN = "Unknown"
    PENDING = "Pending"
    READY   = "Ready"
    FAILED  = "Failed"


class ClientRegistrationTokenStatus(schema.BaseModel):
    """
    The status of a client registration token.
    """
    class Config:
        extra = Extra.allow

    phase: ClientRegistrationTokenPhase = Field(
        ClientRegistrationTokenPhase.UNKNOWN.value,
        description = "The phase of the client registration token."
    )
    id: t.Optional[str] = Field(
        None,
        description = "The id of the token."
    )
    expires: t.Optional[dt.datetime] = Field(
        None,
        description = "The datetime at which the token expires."
    )


class ClientRegistrationToken(
    CustomResource,
    subresources = {"status": {}},
    printer_columns = [
        {
            "name": "Realm",
            "type": "string",
            "jsonPath": ".spec.realmName",
        },
        {
            "name": "Token Secret",
            "type": "string",
            "jsonPath": ".spec.tokenSecretName",
        },
        {
            "name": "Phase",
            "type": "string",
            "jsonPath": ".status.phase",
        },
        {
            "name": "Token ID",
            "type": "string",
            "jsonPath": ".status.id",
        },
        {
            "name": "Token Expires",
            # kubectl won't render date-times in the future properly
            "type": "string",
            "jsonPath": ".status.expires",
        },
    ]
):
    """
    A client registration token.
    """
    spec: ClientRegistrationTokenSpec
    status: ClientRegistrationTokenStatus = Field(default_factory = ClientRegistrationTokenStatus)
