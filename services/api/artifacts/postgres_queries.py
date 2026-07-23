"""Typed PostgreSQL JSON projections for immutable Artifact records."""

ARTIFACT_JSON = """
SELECT json_build_object(
  'id', a.id, 'org_id', a.org_id, 'project_id', a.project_id,
  'name', a.name, 'created_at', a.created_at
)::text
FROM artifacts a
WHERE a.org_id = :org AND a.project_id = :project AND a.id = :identity
"""

VERSION_JSON = """
SELECT json_build_object(
  'id', v.id, 'org_id', v.org_id, 'project_id', v.project_id,
  'artifact_id', v.artifact_id, 'version_no', v.version,
  'object_key', v.object_key, 'content_sha256', v.content_sha256,
  'size_bytes', v.size_bytes, 'media_type', v.media_type,
  'producing_execution_id', v.producing_execution_id,
  'environment_sha256', v.environment_sha256, 'code_sha256', v.code_sha256,
  'runtime_adapter_id', v.runtime_adapter_id,
  'runtime_connection_id', v.runtime_connection_id,
  'skill_content_hashes', v.skill_content_hashes,
  'source_hashes', v.source_hashes,
  'input_version_ids', COALESCE((
    SELECT json_agg(d.input_version_id ORDER BY d.input_version_id)
    FROM artifact_dependencies d
    WHERE d.org_id = v.org_id AND d.project_id = v.project_id
      AND d.artifact_version_id = v.id
  ), '[]'::json),
  'created_at', v.created_at
)::text
FROM artifact_versions v
WHERE v.org_id = :org AND v.project_id = :project AND v.id = :identity
"""
