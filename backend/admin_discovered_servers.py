"""Administrative read access to the same owned server observations as customers."""
import json

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, cast, func, or_
from sqlalchemy.orm import Session

from database import get_db
from models import Assessment, AssetDiscoveryRun, Client, ServerAsset, User
from rbac import require_role

router = APIRouter(tags=['Discovered Customer Servers'])


@router.get('/discovered-servers')
def discovered_servers(
    q: str = Query(default='', max_length=200),
    user_id: int | None = Query(default=None, ge=1),
    client_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(3)),
):
    # Rank before filtering/pagination so old scans cannot inflate current inventory.
    address = func.coalesce(func.nullif(ServerAsset.ip_address, ''), cast(ServerAsset.id, String))
    ranked = db.query(
        ServerAsset.id.label('asset_id'),
        func.row_number().over(partition_by=(ServerAsset.user_id, address),
            order_by=(ServerAsset.last_seen.desc().nullslast(), ServerAsset.id.desc())).label('position'),
    ).subquery()
    query = (db.query(ServerAsset, User, Client, AssetDiscoveryRun)
        .join(ranked, ranked.c.asset_id == ServerAsset.id)
        .join(User, User.id == ServerAsset.user_id)
        .outerjoin(Client, Client.id == User.client_id)
        .join(Assessment, (Assessment.id == ServerAsset.assessment_id) &
                          (Assessment.user_id == ServerAsset.user_id))
        .join(AssetDiscoveryRun, (AssetDiscoveryRun.id == ServerAsset.discovery_run_id) &
              (AssetDiscoveryRun.user_id == ServerAsset.user_id) &
              (AssetDiscoveryRun.assessment_id == ServerAsset.assessment_id))
        .filter(ranked.c.position == 1))
    if user_id is not None:
        query = query.filter(User.id == user_id)
    if client_id is not None:
        query = query.filter(User.client_id == client_id)
    if q.strip():
        term = q.strip().replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        query = query.filter(or_(*(field.ilike('%' + term + '%', escape='\\') for field in (
            ServerAsset.ip_address, ServerAsset.hostname, ServerAsset.target,
            User.username, Client.name))))
    total = query.count()
    rows = query.order_by(ServerAsset.last_seen.desc().nullslast(), ServerAsset.id.desc()).offset(offset).limit(limit).all()
    servers = []
    for asset, owner, client, run in rows:
        try:
            services = json.loads(asset.services_data or '[]')
        except (ValueError, TypeError):
            services = []
        servers.append({
            'id':asset.id, 'owner_user_id':owner.id, 'owner_username':owner.username,
            'client_id':owner.client_id, 'client_name':client.name if client else None,
            'assessment_id':asset.assessment_id, 'discovery_run_id':run.id,
            'hostname':asset.hostname, 'ip_address':asset.ip_address, 'target':asset.target,
            'scan_status':run.status, 'host_status':asset.host_status,
            'open_port_count':asset.open_port_count, 'services':services if isinstance(services, list) else [],
            'last_seen':asset.last_seen.isoformat() if asset.last_seen else None,
        })
    return {'total':total, 'limit':limit, 'offset':offset, 'servers':servers,
            'count_scope':'latest_by_owner_and_address', 'read_only':True}
