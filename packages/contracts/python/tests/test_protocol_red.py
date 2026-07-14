from importlib.util import find_spec


def test_protocol_contracts_exist_when_runtime_boundary_is_required() -> None:
    # Given: the approved Run/runtime protocol boundary.
    module = "science_workbench_contracts.protocols"

    # When: Python resolves the boundary package.
    resolved = find_spec(module)

    # Then: the protocol contracts are implemented as an importable package.
    assert resolved is not None, "Run/runtime protocol contracts are not implemented"
