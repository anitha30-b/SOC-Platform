"""Register one scanner catalogue entry without granting account permissions."""
TOOL = {
    'name': 'Subdomain Discovery', 'category': 'Network Security',
    'description': 'DNSRecon subdomain discovery with shared customer and administrator history.',
    'tool_type': 'discovery',
}


def ensure_subdomain_tool(db):
    from sqlalchemy import func
    from models import SecurityTool
    matches = db.query(SecurityTool).filter(func.lower(SecurityTool.name) == TOOL['name'].lower()).all()
    if len(matches) > 1:
        raise ValueError('Multiple Subdomain Discovery catalogue entries require manual review.')
    if matches:
        tool = matches[0]
        action = 'existing'
        if tool.name != TOOL['name']:
            tool.name = TOOL['name']
            action = 'canonicalized_name'
    else:
        tool = SecurityTool(**TOOL, enabled=True)
        db.add(tool)
        action = 'created'
    db.flush()
    return {'tool_id': tool.id, 'tool_name': tool.name, 'enabled': tool.enabled, 'action': action}


def effective_tool_permissions(db, user):
    """Mirror execution policy: individual override, otherwise role inheritance."""
    from models import SecurityTool, UserToolPermission, RoleToolPermission
    tools = db.query(SecurityTool).order_by(SecurityTool.category, SecurityTool.name).all()
    individual = {row.tool_id: row.allowed for row in db.query(UserToolPermission)
                  .filter(UserToolPermission.user_id == user.id).all()}
    inherited = {row.tool_id: row.allowed for row in db.query(RoleToolPermission)
                 .filter(RoleToolPermission.role_id == user.role_id).all()}
    return [{'tool_id': tool.id, 'tool_name': tool.name, 'category': tool.category,
             'description': tool.description, 'tool_type': tool.tool_type, 'tool_enabled': tool.enabled,
             'allowed': bool(tool.enabled and individual.get(tool.id, inherited.get(tool.id, False))),
             'permission_state': ('allow' if individual[tool.id] else 'deny') if tool.id in individual else 'inherit'}
            for tool in tools]
