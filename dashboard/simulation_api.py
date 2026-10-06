"""
Routes for the simulation layer: load demonstration data through the real connector code, see what is loaded, remove it.

Administrators only. Every route answers 403 with a clear message when simulation is not allowed in this environment
(remediation/utils/environment.py: dev and test allow it; prod needs QUANTA_ALLOW_SIMULATION=true). Loading is a dry-run
preview unless `confirm` is true, like every other route with a side effect. Removing deletes the simulation connections and
the records marked source_mode=simulation; live records are never touched.
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from auth import rbac
from remediation.simulation import service


class LoadBody(BaseModel):
    confirm: bool = False


def build_router():
    r = APIRouter()

    def allowed():
        try:
            service.ensure_allowed()
        except service.SimulationNotAllowed as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @r.get("/api/simulation/status")
    def api_simulation_status(user: dict = Depends(rbac.require_admin)):  # noqa: ARG001
        allowed()
        return service.status()

    @r.post("/api/simulation/load")
    def api_simulation_load(body: LoadBody, user: dict = Depends(rbac.require_admin)):
        allowed()
        if not body.confirm:
            return {"preview_only": True, **service.plan()}
        return {"preview_only": False, **service.load(user["email"])}

    @r.delete("/api/simulation")
    def api_simulation_remove(user: dict = Depends(rbac.require_admin)):
        allowed()
        return service.remove(user["email"])

    return r
