"""Edit the information displayed for a registered service."""

from dataclasses import replace
import json
import sqlite3
import time

from . import auth
from .catalog import Service, get_service, require_idle, service_name, validate_endpoint
from .control import ControlError
from .peer.projection import publish
from .peer.grove_service_admin import GroveServiceAdmin
from .state import State, StateError, audit


def update_service_details(state: State, service_id: str, actor: auth.Actor | GroveServiceAdmin, *,
                           name: str, endpoint: str | None, version: int) -> Service:
    try:
        name = service_name(name)
        validate_endpoint(endpoint or None)
    except StateError as error:
        raise ControlError(422, str(error)) from error
    endpoint = (endpoint.strip() or None) if endpoint is not None else None
    with state.connect(write=True) as db:
        if isinstance(actor, GroveServiceAdmin):
            actor.require(db)
        else:
            session = auth.active_session(db, actor.token_hash, int(time.time()))
            if session is None or session["id"] != actor.account_id:
                raise ControlError(401, "Sign in required")
            if session["role"] != "node_admin":
                raise ControlError(403, "Node administrator required")
        service = get_service(db, service_id)
        if service is None:
            raise ControlError(404, "Unknown service ID")
        same_details = service.name == name and service.spec.get("endpoint") == endpoint
        if same_details and service.version in (version, version + 1):
            return service
        if service.version != version:
            raise ControlError(409, "The service changed. Refresh its details before editing")
        try:
            require_idle(db, service_id)
        except StateError as error:
            raise ControlError(409, str(error)) from error
        spec = {**service.spec, "endpoint": endpoint}
        try:
            db.execute("UPDATE service SET name=?, spec=?, version=version+1 WHERE id=?",
                       (name, json.dumps(spec, sort_keys=True), service_id))
        except sqlite3.IntegrityError as error:
            raise ControlError(409, "Service name is already registered") from error
        publish(db, service_id)
        audit(db, actor.operation_actor, actor.address, "service.details.updated", service_id)
        return replace(service, name=name, spec=spec, version=version + 1)
