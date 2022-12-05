import typing as t

from pydantic import Field, AnyHttpUrl, FilePath, conint, constr, root_validator, validator

from configomatic import Configuration as BaseConfiguration, Section, LoggingConfiguration


class KeycloakConfig(Section):
    """
    Configuration for the target Keycloak instance.
    """
    #: The base URL of the Keycloak instance
    base_url: AnyHttpUrl

    #: The client ID to use when authenticating with Keycloak
    client_id: constr(min_length = 1)
    #: The realm that the client belongs to
    client_realm: constr(min_length = 1) = "master"
    #: The username and password to use when authenticating with Keycloak
    username: constr(min_length = 1)
    password: constr(min_length = 1)

    #: The default expiry for client registration tokens in seconds
    token_default_expiration: conint(gt = 0) = 3600
    #: The default number of clients that a client registration token is allowed to register
    token_default_client_count: conint(gt = 0) = 1

    @validator("base_url")
    def validate_base_url(cls, v):
        """
        Strips trailing slashes from the base URL if present.
        """
        return v.rstrip("/")


class Configuration(BaseConfiguration):
    """
    Top-level configuration model.
    """
    class Config:
        default_path = "/etc/azimuth/identity-operator.yaml"
        path_env_var = "AZIMUTH_IDENTITY_CONFIG"
        env_prefix = "AZIMUTH_IDENTITY"

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "identity.azimuth.stackhpc.com"
    #: A list of categories to place CRDs into
    crd_categories: t.List[constr(min_length = 1)] = Field(
        default_factory = lambda: ["azimuth", "identity", "azimuth-identity"]
    )

    #: The field manager name to use for server-side apply
    easykube_field_manager: constr(min_length = 1) = "azimuth-identity-operator"

    #: Configuration for Keycloak
    keycloak: KeycloakConfig


settings = Configuration()
