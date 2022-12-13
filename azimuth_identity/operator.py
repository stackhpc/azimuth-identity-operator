import base64
import contextlib
import copy
import datetime as dt
import functools
import hashlib
import json
import logging
from secrets import token_urlsafe
import sys
import typing as t

import kopf
import httpx
import yaml

from easykube import Configuration, ApiError
from kube_custom_resource import CustomResourceRegistry
from pyhelm3 import Client as HelmClient, errors as helm_errors

from . import models
from .config import settings
from .models import v1alpha1 as api


logger = logging.getLogger(__name__)


# Create an easykube client from the environment
from pydantic.json import pydantic_encoder
ekclient = (
    Configuration
        .from_environment(json_encoder = pydantic_encoder)
        .async_client(default_field_manager = settings.easykube_field_manager)
)


# Create a Helm client to target the underlying cluster
helm_client = HelmClient(
    default_timeout = settings.helm_client.default_timeout,
    executable = settings.helm_client.executable,
    history_max_revisions = settings.helm_client.history_max_revisions,
    insecure_skip_tls_verify = settings.helm_client.insecure_skip_tls_verify,
    unpack_directory = settings.helm_client.unpack_directory
)


# Create a registry of custom resources and populate it from the models module
registry = CustomResourceRegistry(settings.api_group, settings.crd_categories)
registry.discover_models(models)


@kopf.on.startup()
async def apply_settings(**kwargs):
    """
    Apply kopf settings.
    """
    kopf_settings = kwargs["settings"]
    kopf_settings.persistence.finalizer = f"{settings.api_group}/finalizer"
    kopf_settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix = settings.api_group
    )
    kopf_settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(
        prefix = settings.api_group,
        key = "last-handled-configuration",
    )
    try:
        for crd in registry:
            await ekclient.apply_object(crd.kubernetes_resource(), force = True)
    except Exception:
        logger.exception("error applying CRDs - exiting")
        sys.exit(1)


@kopf.on.cleanup()
async def on_cleanup(**kwargs):
    """
    Runs on operator shutdown.
    """
    await ekclient.aclose()


async def ekresource_for_model(model, subresource = None):
    """
    Returns an easykube resource for the given model.
    """
    api = ekclient.api(f"{settings.api_group}/{model._meta.version}")
    resource = model._meta.plural_name
    if subresource:
        resource = f"{resource}/{subresource}"
    return await api.resource(resource)


async def save_instance_status(instance):
    """
    Save the status of the given instance.
    """
    ekresource = await ekresource_for_model(type(instance), "status")
    data = await ekresource.replace(
        instance.metadata.name,
        {
            # Include the resource version for optimistic concurrency
            "metadata": { "resourceVersion": instance.metadata.resource_version },
            "status": instance.status.dict(exclude_defaults = True),
        },
        namespace = instance.metadata.namespace
    )
    # Store the new resource version
    instance.metadata.resource_version = data["metadata"]["resourceVersion"]


def model_handler(model, register_fn, **kwargs):
    """
    Decorator that registers a handler with kopf for the specified model.
    """
    api_version = f"{settings.api_group}/{model._meta.version}"
    def decorator(func):
        @functools.wraps(func)
        async def handler(**handler_kwargs):
            if "instance" not in handler_kwargs:
                handler_kwargs["instance"] = model.parse_obj(handler_kwargs["body"])
            try:
                return await func(**handler_kwargs)
            except ApiError as exc:
                if exc.status_code == 409:
                    # When a handler fails with a 409, we want to retry quickly
                    raise kopf.TemporaryError(str(exc), delay = 5)
                else:
                    raise
        return register_fn(api_version, model._meta.plural_name, **kwargs)(handler)
    return decorator


@contextlib.asynccontextmanager
async def keycloak_admin_client():
    """
    Context manager for a client that is configured to access the Keycloak admin API.
    """
    async with httpx.AsyncClient(base_url = settings.keycloak.base_url) as client:
        response = await client.post(
            f"/realms/{settings.keycloak.client_realm}/protocol/openid-connect/token",
            data = {
                "grant_type": "password",
                "client_id": settings.keycloak.client_id,
                "username": settings.keycloak.username,
                "password": settings.keycloak.password,
            }
        )
        response.raise_for_status()
        token = response.json()["access_token"]
    admin_base_url = f"{settings.keycloak.base_url}/admin/realms"
    headers = { "Authorization": f"Bearer {token}" }
    async with httpx.AsyncClient(base_url = admin_base_url, headers = headers) as client:
        yield client


def keycloak_realm_name(realm: api.Realm):
    """
    Returns the Keycloak realm name for the given realm.
    """
    # If the realm name is an exact match for the namespace, dedupe it
    # This is the only thing we can do while guaranteeing uniqueness
    if realm.metadata.name == realm.metadata.namespace:
        return realm.metadata.name
    else:
        return f"{realm.metadata.namespace}-{realm.metadata.name}"


async def ensure_dex_tls_secret(realm: api.Realm):
    """
    Ensures that a TLS secret exists for the Dex instance for the realm.

    Returns the TLS secret name.
    """
    # We make the secret as empty, but give it the label that triggers mirroring
    secret_name = f"{realm.metadata.name}-tls"
    secret_data = {
        "metadata": {
            "name": secret_name,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                f"{settings.api_group}/tls-secret": "",
            },
        },
    }
    kopf.adopt(secret_data, realm.dict())
    secrets = await ekclient.api("v1").resource("secrets")
    _ = await secrets.create_or_patch(
        secret_name,
        secret_data,
        namespace = realm.metadata.namespace
    )
    return secret_name


async def ensure_dex_config_secret(realm: api.Realm, tls_enabled: bool):
    """
    Ensures that a Dex config secret exists for the realm.

    Returns the secret name, the config checksum and the client specification.
    """
    secret_name = f"{realm.metadata.name}-dex-conf"
    secrets = await ekclient.api("v1").resource("secrets")
    try:
        secret = await secrets.fetch(secret_name, namespace = realm.metadata.namespace)
    except ApiError as exc:
        if exc.status_code == 404:
            existing_config = {}
        else:
            raise
    else:
        existing_config = yaml.safe_load(base64.b64decode(secret.data["config.yaml"]).decode())
    # Get the existing client secret, if there is one
    try:
        client_secret = existing_config["staticClients"][0]["secret"]
    except (KeyError, IndexError):
        client_secret = token_urlsafe(settings.dex.keycloak_client_secret_bytes)
    # Build the OIDC client config for Keycloak
    client = {
        "name": "Keycloak",
        "redirectURIs": [
            "{base_url}/realms/{realm}/broker/{alias}/endpoint".format(
                base_url = settings.keycloak.base_url,
                realm = keycloak_realm_name(realm),
                alias = settings.dex.keycloak_client_alias
            )
        ],
        "id": "keycloak-oidc",
        "secret": client_secret,
    }
    # Build the full configuration
    next_config = {
        "issuer": "{scheme}://{host}/{prefix}".format(
            scheme = "https" if tls_enabled else "http",
            host = settings.dex.host,
            prefix = keycloak_realm_name(realm)
        ),
        "oauth2": {
            "skipApprovalScreen": True,
        },
        "storage": {
            "type": "kubernetes",
            "config": {
                "inCluster": True,
            },
        },
        "connectors": [
            {
                "type": "authproxy",
                "id": "azimuth",
                "name": "Azimuth",
                "config": {
                    "userHeader": "X-Remote-User",
                    "groupHeader": "X-Remote-Group",
                },
            },
        ],
        "staticClients": [client],
    }
    # Patch the secret if required
    if next_config != existing_config:
        secret_data = {
            "metadata": {
                "name": secret_name,
                "labels": {
                    "app.kubernetes.io/managed-by": "azimuth-identity-operator",
                },
            },
            "stringData": {
                "config.yaml": yaml.safe_dump(next_config),
            },
        }
        kopf.adopt(secret_data, realm.dict())
        _ = await secrets.create_or_patch(
            secret_name,
            secret_data,
            namespace = realm.metadata.namespace
        )
    config_hash = hashlib.sha256(yaml.safe_dump(next_config).encode())
    return secret_name, config_hash.hexdigest(), client


async def ensure_dex_ingresses(realm: api.Realm, tls_secret_name: t.Optional[str] = None):
    """
    Ensures that the ingress resources exist for Dex for the given realm.
    """
    # We need two ingresses for each Dex instance
    # One is unauthenticated and is used for the catchall path
    # The other is authenticated and is used for the authproxy callback path
    ingress_data = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{realm.metadata.name}-dex",
            "namespace": realm.metadata.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            },
            "annotations": {
                **settings.dex.ingress_default_annotations,
                "nginx.ingress.kubernetes.io/configuration-snippet": "proxy_set_header X-Remote-User \"\";",
            },
        },
        "spec": {
            "ingressClassName": settings.dex.ingress_class_name,
            "tls": (
                [
                    {
                        "hosts": [settings.dex.host],
                        "secretName": tls_secret_name,
                    },
                ]
                if tls_secret_name
                else []
            ),
            "rules": [
                {
                    "host": settings.dex.host,
                    "http": {
                        "paths": [
                            {
                                "path": f"/{keycloak_realm_name(realm)}",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": f"{realm.metadata.name}-dex",
                                        "port": {
                                            "name": "http",
                                        },
                                    },
                                },
                            },
                        ],
                    },
                },
            ],
        },
    }
    kopf.adopt(ingress_data)
    _ = await ekclient.apply_object(ingress_data, force = True)
    auth_annotations = {
        "nginx.ingress.kubernetes.io/auth-url": settings.dex.ingress_auth_url,
        # Include the tenancy ID as a header for the auth request
        # This means that only users that belong to the tenancy will be considered authenticated
        "nginx.ingress.kubernetes.io/auth-snippet": (
            f"proxy_set_header X-Auth-Tenancy-Id \"{realm.spec.tenancy_id}\";"
        ),
        # Forward the X-Remote-{User,Group} headers from the auth response to the upstream
        "nginx.ingress.kubernetes.io/auth-response-headers": "X-Remote-User,X-Remote-Group",
    }
    if settings.dex.ingress_auth_signin_url:
        auth_annotations.update({
            "nginx.ingress.kubernetes.io/auth-signin": settings.dex.ingress_auth_signin_url,
            "nginx.ingress.kubernetes.io/auth-signin-redirect-param": settings.dex.ingress_auth_signin_redirect_param,
        })
    ingress_data = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {
            "name": f"{realm.metadata.name}-dex-auth",
            "namespace": realm.metadata.namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "azimuth-identity-operator",
            },
            "annotations": {
                **settings.dex.ingress_default_annotations,
                **auth_annotations,
            }
        },
        "spec": {
            "ingressClassName": settings.dex.ingress_class_name,
            "tls": (
                [
                    {
                        "hosts": [settings.dex.host],
                        "secretName": tls_secret_name,
                    },
                ]
                if tls_secret_name
                else []
            ),
            "rules": [
                {
                    "host": settings.dex.host,
                    "http": {
                        "paths": [
                            {
                                "path": f"/{keycloak_realm_name(realm)}/callback/azimuth",
                                "pathType": "Prefix",
                                "backend": {
                                    "service": {
                                        "name": f"{realm.metadata.name}-dex",
                                        "port": {
                                            "name": "http",
                                        },
                                    },
                                },
                            },
                        ],
                    },
                },
            ],
        },
    }
    kopf.adopt(ingress_data)
    _ = await ekclient.apply_object(ingress_data, force = True)


async def ensure_keycloak_admins_group(kc_client, realm: api.Realm):
    """
    Ensures that the Keycloak admins group is set up and has the required roles.
    """
    realm_name = keycloak_realm_name(realm)
    # Get the existing group, if one exists
    response = await kc_client.get(
        f"/{realm_name}/groups",
        params = {
            "briefRepresentation": "false",
            "q": settings.keycloak.admins_group_name,
            "exact": "true",
        }
    )
    response.raise_for_status()
    try:
        group = next(
            group
            for group in response.json()
            if group["name"] == settings.keycloak.admins_group_name
        )
    except StopIteration:
        response = await kc_client.post(
            f"{realm_name}/groups",
            json = { "name": settings.keycloak.admins_group_name }
        )
        response.raise_for_status()
        # The Keycloak API does not return a representation in the create response,
        # but it does return the URL to get one in the location header
        response = await kc_client.get(response.headers["location"])
        response.raise_for_status()
        group = response.json()
        _ = group.pop("access", None)
    # Make sure that the group has all the client roles that are configured
    # We need to turn client names into IDs, so load all the clients and index them
    response = await kc_client.get(f"/{realm_name}/clients")
    response.raise_for_status()
    client_ids = { client["clientId"]: client["id"] for client in response.json() }
    for client_name, roles in settings.keycloak.admins_group_client_roles.items():
        existing_roles = group.get("clientRoles", {}).get(client_name, [])
        missing_roles = [role for role in roles if role not in existing_roles]
        if missing_roles:
            client_id = client_ids[client_name]
            # We need to get the ID for each role, so load the available client roles and index them
            response = await kc_client.get(
                f"/{realm_name}/groups/{group['id']}/role-mappings/clients/{client_id}/available"
            )
            response.raise_for_status()
            role_ids = { role["name"]: role["id"] for role in response.json() }
            response = await kc_client.post(
                f"/{realm_name}/groups/{group['id']}/role-mappings/clients/{client_id}",
                json = [{ "id": role_ids[role], "name": role } for role in missing_roles]
            )
            response.raise_for_status()


async def ensure_keycloak_identity_provider(kc_client, realm: api.Realm, dex_client):
    """
    Ensures that a Keycloak identity provider exists for the given realm.
    """
    realm_name = keycloak_realm_name(realm)
    idp_url = f"/{realm_name}/identity-provider/instances/{settings.dex.keycloak_client_alias}"
    # Get the existing IDP as a starting base
    response = await kc_client.get(idp_url)
    if response.status_code == 404:
        existing_idp = {}
    else:
        response.raise_for_status()
        existing_idp = response.json()
    # Update with what we think the IDP should look like
    next_idp = copy.deepcopy(existing_idp)
    next_idp.update({
        "providerId": "oidc",
        "enabled": True,
        "alias": settings.dex.keycloak_client_alias,
        "displayName": "Azimuth",
        "updateProfileFirstLoginMode": "off",
    })
    issuer = "{scheme}://{host}/{prefix}".format(
        scheme = "https" if settings.dex.tls_secret else "http",
        host = settings.dex.host,
        prefix = realm_name
    )
    next_idp.setdefault("config", {}).update({
        "issuer": issuer,
        "authorizationUrl": f"{issuer}/auth",
        "tokenUrl": f"{issuer}/token",
        "userInfoUrl": f"{issuer}/userinfo",
        "useJwksUrl": "true",
        "validateSignature": "true",
        "jwksUrl": f"{issuer}/keys",
        "clientAuthMethod": "client_secret_post",
        "clientId": dex_client["id"],
        "clientSecret": dex_client["secret"],
        "syncMode": "IMPORT",
        "defaultScope": "openid profile email groups",
    })
    # Update the identity provider in Keycloak if required
    if not existing_idp:
        response = await kc_client.post(
            f"/{realm_name}/identity-provider/instances",
            json = next_idp
        )
        response.raise_for_status()
    elif existing_idp != next_idp:
        response = await kc_client.put(idp_url, json = next_idp)
        response.raise_for_status()
    # Get the existing realm-admins mapper
    response = await kc_client.get(f"{idp_url}/mappers")
    response.raise_for_status()
    try:
        existing_mapper = next(
            mapper
            for mapper in response.json()
            if mapper["name"] == "realm-admin"
        )
    except StopIteration:
        existing_mapper = {}
    # Update with what the mapper should look like
    next_mapper = copy.deepcopy(existing_mapper)
    next_mapper.update({
        "name": "realm-admin",
        "identityProviderAlias": settings.dex.keycloak_client_alias,
        "identityProviderMapper": "oidc-advanced-group-idp-mapper",
    })
    next_mapper.setdefault("config", {}).update({
        "claims": json.dumps([
            {
                "key": "groups",
                "value": realm.spec.tenancy_id,
            },
        ]),
        "syncMode": "FORCE",
        "are.claim.values.regex": "false",
        "group": f"/{settings.keycloak.admins_group_name}"
    })
    # Update the mapper in Keycloak if required
    if not existing_mapper:
        response = await kc_client.post(f"{idp_url}/mappers", json = next_mapper)
        response.raise_for_status()
    elif existing_mapper != next_mapper:
        response = await kc_client.put(
            f"{idp_url}/mappers/{existing_mapper['id']}",
            json = next_mapper
        )
        response.raise_for_status()


@model_handler(api.Realm, kopf.on.create)
@model_handler(api.Realm, kopf.on.update, field = "spec")
@model_handler(api.Realm, kopf.on.resume)
async def reconcile_realm(instance: api.Realm, **kwargs):
    """
    Handles the reconciliation of a realm.
    """
    if instance.status.phase == api.RealmPhase.UNKNOWN:
        instance.status.phase = api.RealmPhase.PENDING
        await save_instance_status(instance)
    realm_name = keycloak_realm_name(instance)
    # Configure the TLS certificate for Dex
    if settings.dex.tls_secret:
        tls_secret_name = await ensure_dex_tls_secret(instance)
    else:
        tls_secret_name = None
    # Generate the Dex configuration
    conf_secret_name, conf_checksum, dex_client = await ensure_dex_config_secret(
        instance,
        tls_secret_name is not None
    )
    # Create the Dex instance for the realm
    _ = await helm_client.ensure_release(
        f"{instance.metadata.name}-dex",
        await helm_client.get_chart(
            settings.dex.chart_name,
            repo = settings.dex.chart_repo,
            version = settings.dex.chart_version
        ),
        settings.dex.default_values,
        {
            "configSecret": {
                "create": False,
                "name": conf_secret_name,
            },
            "podAnnotations": {
                "checksum/config": conf_checksum,
            },
        },
        namespace = instance.metadata.namespace,
        # The target namespace already exists, because the realm is in it
        create_namespace = False
    )
    # Generate the ingresses for Dex
    await ensure_dex_ingresses(instance, tls_secret_name)
    async with keycloak_admin_client() as kc_client:
        # First, ensure that a realm with the given name exists
        response = await kc_client.post("/", json = { "realm": realm_name })
        if response.status_code != 409:
            response.raise_for_status()
        response = await kc_client.get(f"/{realm_name}")
        response.raise_for_status()
        realm = response.json()
        # Enable the realm if required
        if not realm.get("enabled"):
            realm["enabled"] = True
            response = await kc_client.put(f"/{realm_name}", json = realm)
            response.raise_for_status()
        await ensure_keycloak_admins_group(kc_client, instance)
        await ensure_keycloak_identity_provider(kc_client, instance, dex_client)
    instance.status.phase = api.RealmPhase.READY
    instance.status.oidc_issuer_url = f"{settings.keycloak.base_url}/realms/{realm_name}"
    await save_instance_status(instance)


@model_handler(api.Realm, kopf.on.delete)
async def delete_realm(instance: api.Realm, **kwargs):
    """
    Handes the deletion of a realm.
    """
    # Delete the Dex release for the realm
    _ = await helm_client.uninstall_release(
        f"{instance.metadata.name}-dex",
        namespace = instance.metadata.namespace
    )
    # Remove the realm from Keycloak
    realm_name = keycloak_realm_name(instance)
    async with keycloak_admin_client() as client:
        response = await client.delete(f"/{realm_name}")
        # Not found is fine - it means the realm doesn't exist
        if response.status_code != 404:
            response.raise_for_status()


@kopf.on.daemon(
    "v1",
    "secrets",
    labels = { f"{settings.api_group}/tls-secret": kopf.PRESENT },
    cancellation_timeout = 1
)
async def reconcile_tls_secret(name, namespace, **kwargs):
    """
    Reconciles the secret by copying the configured TLS secret.
    """
    if not settings.dex.tls_secret:
        return
    secrets = await ekclient.api("v1").resource("secrets")
    initial, events = await secrets.watch_one(
        settings.dex.tls_secret.name,
        namespace = settings.dex.tls_secret.namespace
    )
    if initial:
        _ = await secrets.patch(
            name,
            { "data": initial["data"] },
            namespace = namespace
        )
    async for event in events:
        # Ignore delete events and just leave the secret in place
        if event["type"] == "DELETED":
            return
        if "object" in event:
            _ = await secrets.patch(
                name,
                { "data": event["object"]["data"] },
                namespace = namespace
            )


@model_handler(api.ClientRegistrationToken, kopf.on.create)
@model_handler(api.ClientRegistrationToken, kopf.on.update, field = "spec")
@model_handler(api.ClientRegistrationToken, kopf.on.resume)
async def reconcile_token(instance: api.ClientRegistrationToken, **kwargs):
    """
    Handles the reconciliation of a client registration token.
    """
    # If the status is ready, there is nothing to do
    if instance.status.phase == api.ClientRegistrationTokenPhase.READY:
        return
    if instance.status.phase == api.ClientRegistrationTokenPhase.UNKNOWN:
        instance.status.phase = api.ClientRegistrationTokenPhase.PENDING
        await save_instance_status(instance)
    realms = await ekresource_for_model(api.Realm)
    try:
        realm_data = await realms.fetch(
            instance.spec.realm_name,
            namespace = instance.metadata.namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            raise kopf.TemporaryError(f"realm '{instance.spec.realm_name}' does not exist")
        else:
            raise
    else:
        realm = api.Realm.parse_obj(realm_data)
    if realm.status.phase != api.RealmPhase.READY:
        raise kopf.TemporaryError(f"realm '{instance.spec.realm_name}' is not ready")
    realm_name = keycloak_realm_name(realm)
    async with keycloak_admin_client() as client:
        response = await client.post(
            f"/{realm_name}/clients-initial-access",
            json = {
                "expiration": instance.spec.token_expiration,
                "count": instance.spec.token_client_count,
            }
        )
        response.raise_for_status()
        response_data = response.json()
    # Put the token into the named secret
    secret_data = {
        "metadata": {
            "name": instance.spec.token_secret_name,
        },
        "stringData": {
            instance.spec.token_secret_key: response_data["token"],
        },
    }
    # Make sure that the secret is owned by the token object
    kopf.adopt(secret_data, instance.dict())
    secrets = await ekclient.api("v1").resource("secrets")
    _ = await secrets.create_or_patch(
        instance.spec.token_secret_name,
        secret_data,
        namespace = instance.metadata.namespace
    )
    instance.status.phase = api.ClientRegistrationTokenPhase.READY
    instance.status.id = response_data["id"]
    # Compute the expiry from the returned timestamp and exipiration
    instance.status.expires = dt.datetime.fromtimestamp(
        response_data["timestamp"] + response_data["expiration"],
        dt.timezone.utc
    )
    await save_instance_status(instance)


@model_handler(api.ClientRegistrationToken, kopf.on.delete)
async def delete_token(instance: api.ClientRegistrationToken, **kwargs):
    """
    Handles the deletion of a client registration token.
    """
    # If the token has no ID, we can't delete it
    if not instance.status.id:
        return
    realms = await ekresource_for_model(api.Realm)
    try:
        realm_data = await realms.fetch(
            instance.spec.realm_name,
            namespace = instance.metadata.namespace
        )
    except ApiError as exc:
        if exc.status_code == 404:
            # If the realm doesn't exist, we can't delete the token
            return
        else:
            raise
    else:
        realm = api.Realm.parse_obj(realm_data)
    realm_name = keycloak_realm_name(realm)
    async with keycloak_admin_client() as client:
        response = await client.delete(
            f"/{realm_name}/clients-initial-access/{instance.status.id}"
        )
        if response.status_code == 404:
            # If the token doesn't exist in Keycloak, we are done
            return
        else:
            response.raise_for_status()
