from types import MappingProxyType

from science_workbench_contracts.protocols.models import RunEvent

from .protocol_fixtures import protocol_fixture


def test_run_event_nested_data_is_immutable_after_validation() -> None:
    # Given: mutable nested input accepted at the RunEvent boundary.
    source = {"analysis": [{"message": "measured"}]}
    template = protocol_fixture().event_window.events[0]

    # When: the source and accepted nested record are attacked after validation.
    event = RunEvent.model_validate({**template.model_dump(), "data": source})
    serialized = event.model_dump(mode="json")
    source["analysis"][0]["Authorization"] = "Bearer " + ("x" * 24)

    # Then: recursive immutable containers preserve the validated wire state.
    assert isinstance(event.data, MappingProxyType)
    analysis = event.data["analysis"]
    assert isinstance(analysis, tuple)
    assert isinstance(analysis[0], MappingProxyType)
    assert event.model_dump(mode="json") == serialized
    assert RunEvent.model_validate_json(event.model_dump_json()) == event
