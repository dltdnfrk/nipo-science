"""Complete direct database authority inventory for provider service roles."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection


async def database_role_direct_acls(
    database: AsyncConnection, *, role_name: str
) -> frozenset[str]:
    """Return direct ACLs across every PostgreSQL object class used by GRANT."""
    rows = await database.execute(
        text(
            "WITH target AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "direct_acl AS (SELECT 'schema:' || n.nspname || ':' || "
            "entry.privilege_type AS item, entry.is_grantable FROM pg_namespace n, "
            "target, LATERAL "
            "aclexplode(n.nspacl) entry WHERE entry.grantee = target.oid UNION ALL "
            "SELECT 'table:' || n.nspname || '.' || c.relname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_class c JOIN "
            "pg_namespace n ON n.oid = c.relnamespace, target, LATERAL "
            "aclexplode(c.relacl) entry WHERE "
            "entry.grantee = target.oid UNION ALL SELECT 'column:' || n.nspname || "
            "'.' || c.relname || '.' || a.attname || ':' || entry.privilege_type, "
            "entry.is_grantable FROM pg_class c JOIN pg_namespace n ON n.oid = "
            "c.relnamespace JOIN "
            "pg_attribute a ON a.attrelid = c.oid, target, LATERAL "
            "aclexplode(a.attacl) entry WHERE entry.grantee = target.oid UNION ALL "
            "SELECT 'function:' || n.nspname || '.' || p.oid::regprocedure::text || "
            "':' || entry.privilege_type, entry.is_grantable FROM pg_proc p JOIN "
            "pg_namespace n ON "
            "n.oid = p.pronamespace, target, LATERAL aclexplode(p.proacl) entry "
            "WHERE entry.grantee = target.oid UNION ALL SELECT 'type:' || "
            "n.nspname || '.' || t.typname || ':' || entry.privilege_type, "
            "entry.is_grantable FROM pg_type t JOIN pg_namespace n ON n.oid = "
            "t.typnamespace, target, "
            "LATERAL aclexplode(t.typacl) entry WHERE entry.grantee = target.oid "
            "UNION ALL SELECT 'database:' || d.datname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_database d, target, "
            "LATERAL "
            "aclexplode(d.datacl) entry WHERE entry.grantee = target.oid UNION ALL "
            "SELECT 'foreign_data_wrapper:' || wrapper.fdwname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_foreign_data_wrapper "
            "wrapper, target, LATERAL aclexplode(wrapper.fdwacl) entry WHERE "
            "entry.grantee = "
            "target.oid UNION ALL SELECT 'foreign_server:' || server.srvname || ':' "
            "|| entry.privilege_type, entry.is_grantable FROM pg_foreign_server "
            "server, target, LATERAL "
            "aclexplode(server.srvacl) entry WHERE entry.grantee = target.oid UNION "
            "ALL SELECT 'language:' || language.lanname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_language language, "
            "target, LATERAL aclexplode(language.lanacl) entry WHERE entry.grantee = "
            "target.oid "
            "UNION ALL SELECT 'tablespace:' || tablespace.spcname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_tablespace tablespace, "
            "target, LATERAL aclexplode(tablespace.spcacl) entry WHERE entry.grantee "
            "= target.oid "
            "UNION ALL SELECT 'large_object:' || large_object.oid::text || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_largeobject_metadata "
            "large_object, target, LATERAL aclexplode(large_object.lomacl) entry "
            "WHERE entry.grantee = "
            "target.oid UNION ALL SELECT 'parameter:' || parameter.parname || ':' || "
            "entry.privilege_type, entry.is_grantable FROM pg_parameter_acl "
            "parameter, target, LATERAL "
            "aclexplode(parameter.paracl) entry WHERE entry.grantee = target.oid "
            "UNION ALL SELECT 'default_acl:' || owner.rolname || ':' || COALESCE("
            "namespace.nspname, '<global>') || ':' || defaults.defaclobjtype::text "
            "|| ':' || entry.privilege_type, entry.is_grantable FROM pg_default_acl "
            "defaults JOIN pg_roles owner ON owner.oid = defaults.defaclrole LEFT "
            "JOIN pg_namespace namespace ON namespace.oid = defaults."
            "defaclnamespace, target, LATERAL aclexplode(defaults.defaclacl) entry "
            "WHERE entry.grantee = target.oid) "
            "SELECT item || CASE WHEN is_grantable THEN '|WITH_GRANT_OPTION' ELSE '' "
            "END FROM direct_acl ORDER BY item, is_grantable"
        ),
        {"role": role_name},
    )
    return frozenset(cast("str", row[0]) for row in rows)


async def database_has_public_sensitive_authority(
    database: AsyncConnection,
) -> bool:
    """Reject PUBLIC authority on provider-relevant user and external objects."""
    result = await database.execute(
        text(
            "SELECT EXISTS (SELECT 1 FROM pg_namespace namespace, LATERAL "
            "aclexplode(namespace.nspacl) entry WHERE namespace.nspname <> "
            "'information_schema' AND namespace.nspname NOT LIKE 'pg\\_%' ESCAPE "
            "'\\' AND entry.grantee = 0 AND (namespace.nspname <> 'public' OR entry."
            "privilege_type <> 'USAGE') UNION ALL "
            "SELECT 1 FROM pg_class relation JOIN pg_namespace namespace ON "
            "namespace.oid = relation.relnamespace, LATERAL aclexplode(relation."
            "relacl) entry WHERE namespace.nspname <> 'information_schema' AND "
            "namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND relation.relkind "
            "IN ('r', 'p', 'v', 'm', 'f', 'S') AND entry.grantee = 0 UNION ALL "
            "SELECT 1 FROM pg_attribute column_acl JOIN pg_class relation ON "
            "relation.oid = column_acl.attrelid JOIN pg_namespace namespace ON "
            "namespace.oid = relation.relnamespace, LATERAL aclexplode(column_acl."
            "attacl) entry WHERE namespace.nspname <> 'information_schema' AND "
            "namespace.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND NOT column_acl."
            "attisdropped AND entry.grantee = 0 UNION ALL SELECT 1 FROM "
            "pg_foreign_data_wrapper wrapper, LATERAL aclexplode(wrapper.fdwacl) "
            "entry WHERE entry.grantee = 0 UNION ALL SELECT 1 FROM "
            "pg_foreign_server server, LATERAL aclexplode(server.srvacl) entry "
            "WHERE entry.grantee = 0 UNION ALL SELECT 1 FROM "
            "pg_largeobject_metadata large_object, LATERAL aclexplode(large_object."
            "lomacl) entry WHERE entry.grantee = 0 UNION ALL SELECT 1 FROM "
            "pg_tablespace tablespace, LATERAL aclexplode(tablespace.spcacl) entry "
            "WHERE entry.grantee = 0 UNION ALL SELECT 1 FROM pg_parameter_acl "
            "parameter, LATERAL aclexplode(parameter.paracl) entry WHERE entry."
            "grantee = 0 UNION ALL SELECT 1 FROM pg_default_acl defaults, LATERAL "
            "aclexplode(defaults.defaclacl) entry WHERE entry.grantee = 0 UNION ALL "
            "SELECT 1 FROM pg_database database_acl, LATERAL aclexplode(database_acl."
            "datacl) entry WHERE entry.grantee = 0 AND entry.privilege_type = "
            "'CREATE')"
        )
    )
    return cast("bool", result.scalar_one())


async def database_role_owns_objects(
    database: AsyncConnection, *, role_name: str
) -> bool:
    """Report ownership across the object catalogs that carry role-owned authority."""
    return bool(
        await database_role_owned_object_inventory(database, role_name=role_name)
    )


async def database_role_owned_object_inventory(
    database: AsyncConnection, *, role_name: str
) -> frozenset[str]:
    """Return every directly role-owned database object in canonical form."""
    rows = await database.execute(
        text(
            "WITH target AS (SELECT oid FROM pg_roles WHERE rolname = :role), "
            "owned(item) AS (SELECT 'relation:' || namespace.nspname || '.' || "
            "relation.relname FROM pg_class relation JOIN pg_namespace namespace "
            "ON namespace.oid = relation.relnamespace, target WHERE relation."
            "relowner = target.oid UNION ALL SELECT 'function:' || namespace."
            "nspname || '.' || function.oid::regprocedure::text FROM pg_proc "
            "function JOIN pg_namespace namespace ON namespace.oid = function."
            "pronamespace, target WHERE function.proowner = target.oid UNION ALL "
            "SELECT 'schema:' || namespace.nspname FROM pg_namespace namespace, "
            "target WHERE namespace.nspowner = target.oid UNION ALL SELECT 'type:' "
            "|| namespace.nspname || '.' || type.typname FROM pg_type type JOIN "
            "pg_namespace namespace ON namespace.oid = type.typnamespace, target "
            "WHERE type.typowner = target.oid UNION ALL SELECT 'database:' || "
            "database.datname FROM pg_database database, target WHERE database."
            "datdba = target.oid UNION ALL SELECT 'foreign_data_wrapper:' || "
            "wrapper.fdwname FROM pg_foreign_data_wrapper wrapper, target WHERE "
            "wrapper.fdwowner = target.oid UNION ALL SELECT 'foreign_server:' || "
            "server.srvname FROM pg_foreign_server server, target WHERE server."
            "srvowner = target.oid UNION ALL SELECT 'language:' || language.lanname "
            "FROM pg_language language, target WHERE language.lanowner = target.oid "
            "UNION ALL SELECT 'tablespace:' || tablespace.spcname FROM pg_tablespace "
            "tablespace, target WHERE tablespace.spcowner = target.oid UNION ALL "
            "SELECT 'large_object:' || object.oid::text FROM "
            "pg_largeobject_metadata object, target WHERE object.lomowner = target."
            "oid UNION ALL SELECT 'other:' || pg_describe_object(dependency.classid, "
            "dependency.objid, dependency.objsubid) FROM pg_shdepend dependency, "
            "target WHERE dependency.refclassid = 'pg_authid'::regclass AND "
            "dependency.refobjid = target.oid AND dependency.deptype = 'o' AND "
            "dependency.classid NOT IN ('pg_class'::regclass, 'pg_proc'::regclass, "
            "'pg_namespace'::regclass, 'pg_type'::regclass, 'pg_database'::regclass, "
            "'pg_foreign_data_wrapper'::regclass, 'pg_foreign_server'::regclass, "
            "'pg_language'::regclass, 'pg_tablespace'::regclass, "
            "'pg_largeobject_metadata'::regclass)) SELECT item FROM owned ORDER BY item"
        ),
        {"role": role_name},
    )
    return frozenset(cast("str", row[0]) for row in rows)
