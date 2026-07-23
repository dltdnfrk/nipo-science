"""Lifecycle orchestration for version-pinned provider cleanup functions."""

from services.api.migrations.versioned_0004_cleanup_completion import (
    create_cleanup_completion_functions,
    drop_cleanup_completion_functions,
    revoke_public_cleanup_completion_functions,
)
from services.api.migrations.versioned_0004_cleanup_eligibility import (
    create_cleanup_eligibility_functions,
    drop_cleanup_eligibility_functions,
    revoke_public_cleanup_eligibility_functions,
)
from services.api.migrations.versioned_0004_cleanup_validation import (
    create_cleanup_validation_function,
    drop_cleanup_validation_function,
    revoke_public_cleanup_validation_function,
)


def create_cleanup_functions() -> None:
    """Replace all cleanup functions and keep their PUBLIC ACLs closed."""
    drop_cleanup_functions()
    create_cleanup_eligibility_functions()
    create_cleanup_validation_function()
    create_cleanup_completion_functions()
    revoke_public_cleanup_eligibility_functions()
    revoke_public_cleanup_validation_function()
    revoke_public_cleanup_completion_functions()


def drop_cleanup_functions() -> None:
    """Drop all cleanup functions in the original migration order."""
    drop_cleanup_eligibility_functions()
    drop_cleanup_validation_function()
    drop_cleanup_completion_functions()
