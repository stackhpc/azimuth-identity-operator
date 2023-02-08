import typing as t

from pydantic import Field, AnyHttpUrl, FilePath, conint, constr, root_validator, validator

from configomatic import Configuration as BaseConfiguration, Section, LoggingConfiguration


class SecretRef(Section):
    """
    A reference to a secret.
    """
    #: The name of the secret
    name: constr(min_length = 1)
    #: The namespace of the secret
    namespace: constr(min_length = 1)


class DexConfig(Section):
    """
    Configuration for the Dex instances that authenticate with Azimuth.
    """
    #: The Helm chart repo, name and version to use for Dex instances
    chart_repo: AnyHttpUrl = "https://charts.dexidp.io"
    chart_name: constr(min_length = 1) = "dex"
    chart_version: constr(min_length = 1) = "0.12.1"

    #: Default Helm values to merge with calculated values for Dex releases
    default_values: t.Dict[str, t.Any] = Field(default_factory = dict)

    #: The host to use for Dex instances
    #: The realm instances will be provisioned using subpaths on this host
    host: constr(min_length = 1)

    #: The name of the secret containing the TLS secret for the host
    #: If it is given, Dex instances will have TLS enabled
    tls_secret: t.Optional[SecretRef] = None

    #: The ingress class to use for ingress resources
    #: Note that only the NGINX ingress controller is currently supported
    ingress_class_name: constr(min_length = 1) = "nginx"
    #: The default annotations for the ingress resources
    ingress_default_annotations: t.Dict[str, str] = Field(default_factory = dict)
    #: The auth URL to use for the ingress auth subrequest
    ingress_auth_url: AnyHttpUrl
    #: The URL that unauthenticated users should be redirected to to sign in
    ingress_auth_signin_url: t.Optional[AnyHttpUrl] = None
    #: The HTTP parameter to put the next URL in when redirecting to sign in
    ingress_auth_signin_redirect_param: str = "next"

    #: The alias to use for the Keycloak client
    keycloak_client_alias: constr(min_length = 1) = "azimuth"
    #: The number of bytes to use for the client secret
    keycloak_client_secret_bytes: conint(gt = 0) = 64


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

    #: Indicates if SSL is required for external requests
    ssl_required: bool = True

    #: The default expiry for client registration tokens in seconds
    token_default_expiration: conint(gt = 0) = 3600
    #: The default number of clients that a client registration token is allowed to register
    token_default_client_count: conint(gt = 0) = 1

    #: The name to use for the admins group in each realm
    admins_group_name: constr(min_length = 1) = "admins"
    #: The client roles to ensure are present in the admins group
    #: The value is a mapping of client => list of roles for client
    admins_group_client_roles: t.Dict[str, t.List[str]] = Field(
        default_factory = lambda: { "realm-management": ["realm-admin"] }
    )

    @validator("base_url")
    def validate_base_url(cls, v):
        """
        Strips trailing slashes from the base URL if present.
        """
        return v.rstrip("/")


class HelmClientConfiguration(Section):
    """
    Configuration for the Helm client.
    """
    #: The default timeout to use with Helm releases
    #: Can be an integer number of seconds or a duration string like 5m, 5h
    default_timeout: t.Union[int, constr(min_length = 1)] = "5m"
    #: The executable to use
    #: By default, we assume Helm is on the PATH
    executable: constr(min_length = 1) = "helm"
    #: The maximum number of revisions to retain in the history of releases
    history_max_revisions: int = 10
    #: Indicates whether to verify TLS when pulling charts
    insecure_skip_tls_verify: bool = False
    #: The directory to use for unpacking charts
    #: By default, the system temporary directory is used
    unpack_directory: t.Optional[str] = None


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

    #: Configuration for Dex instances
    dex: DexConfig

    #: Configuration for Keycloak
    keycloak: KeycloakConfig

    #: The Helm client configuration
    helm_client: HelmClientConfiguration = Field(default_factory = HelmClientConfiguration)


settings = Configuration()
