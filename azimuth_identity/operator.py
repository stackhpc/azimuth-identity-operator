import contextlib
import datetime as dt
import functools
import logging
import sys

import kopf
import httpx

from easykube import Configuration, ApiError
from kube_custom_resource import CustomResourceRegistry

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
    admin_base_url = f"{settings.keycloak.base_url}/admin"
    headers = { "Authorization": f"Bearer {token}" }
    async with httpx.AsyncClient(base_url = admin_base_url, headers = headers) as client:
        yield client


def keycloak_realm_name(realm: api.Realm):
    """
    Returns the Keycloak realm name for the given realm.
    """
    # The realm name is a combination of the namespace and name
    # If the name starts with the namespace, we dedupe it
    if realm.metadata.name.startswith(realm.metadata.namespace):
        return realm.metadata.name
    else:
        return f"{realm.metadata.namespace}-{realm.metadata.name}"


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
    async with keycloak_admin_client() as client:
        response = await client.post(
            "/realms",
            json = {
                "realm": realm_name,
            }
        )
        # The conflict status is fine - that means the realm already exists
        # Any other non-success status is an error
        if response.status_code != 409:
            response.raise_for_status()
    instance.status.phase = api.RealmPhase.READY
    instance.status.oidc_issuer_url = f"{settings.keycloak.base_url}/realms/{realm_name}"
    await save_instance_status(instance)


@model_handler(api.Realm, kopf.on.delete)
async def delete_realm(instance: api.Realm, **kwargs):
    """
    Handes the deletion of a realm.
    """
    realm_name = keycloak_realm_name(instance)
    async with keycloak_admin_client() as client:
        response = await client.delete(f"/realms/{realm_name}")
        # Not found is fine - it means the realm doesn't exist
        if response.status_code != 404:
            response.raise_for_status()


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
            f"/realms/{realm_name}/clients-initial-access",
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
            f"/realms/{realm_name}/clients-initial-access/{instance.status.id}"
        )
        if response.status_code == 404:
            # If the token doesn't exist in Keycloak, we are done
            return
        else:
            response.raise_for_status()
