from typing import Final, Self

from pydantic import model_validator
from pydantic_core import PydanticCustomError

from .models import (
    ActionPlan,
    ApprovalRecord,
    ExecutionRecord,
    Message,
    ProtocolModel,
    RunRecord,
    ToolGrant,
)
from .runtime import (
    RuntimeActionProposal,
    RuntimeContinue,
    RuntimeEvent,
    RuntimeTextDelta,
)
from .sse import RunEventWindow

FIXTURE_CORRELATION_ERROR: Final = "protocol_fixture_correlation"
FIXTURE_CORRELATION_MESSAGE: Final = "protocol fixture references do not correlate"


class ProtocolFixture(ProtocolModel):
    run: RunRecord
    messages: tuple[Message, ...]
    event_window: RunEventWindow
    action_plan: ActionPlan
    tool_grant: ToolGrant
    approval: ApprovalRecord
    execution: ExecutionRecord
    runtime_events: tuple[RuntimeEvent, ...]
    runtime_action_proposal: RuntimeActionProposal
    runtime_continuation: RuntimeContinue

    @model_validator(mode="after")
    def correlated_records(self) -> Self:
        run = self.run
        plan = self.action_plan
        binding = self.approval.binding
        message_ids = {message.id for message in self.messages}
        messages_match = all(
            message.org_id == run.org_id and message.run_id == run.id
            for message in self.messages
        )
        events_match = all(event.run_id == run.id for event in self.event_window.events)
        runtime_events_match = all(
            event.run_id == run.id for event in self.runtime_events
        )
        runtime_messages_match = all(
            event.message_id in message_ids
            for event in self.runtime_events
            if isinstance(event, RuntimeTextDelta | RuntimeActionProposal)
        )
        plan_matches = (
            plan.org_id == run.org_id
            and plan.run_id == run.id
            and plan.requester_id == run.requester_id
            and self.tool_grant.org_id == plan.org_id
            and self.tool_grant.project_id == plan.project_id
        )
        binding_matches = (
            binding.org_id == plan.org_id
            and binding.project_id == plan.project_id
            and binding.run_id == plan.run_id
            and binding.requester_id == plan.requester_id
            and binding.action_plan_id == plan.id
            and binding.plan_digest == plan.plan_digest
        )
        execution_matches = (
            self.execution.org_id == run.org_id
            and self.execution.run_id == run.id
            and self.execution.action_plan_id == plan.id
        )
        proposal = self.runtime_action_proposal
        continuation = self.runtime_continuation
        runtime_matches = (
            proposal in self.runtime_events
            and proposal.run_id == run.id
            and proposal.message_id in message_ids
            and continuation.org_id == run.org_id
            and continuation.run_id == run.id
            and continuation.message_id == proposal.message_id
            and continuation.action_id == proposal.action_id
            and continuation.execution_id == self.execution.id
            and continuation.result.execution_id == self.execution.id
        )
        if not all(
            (
                messages_match,
                events_match,
                runtime_events_match,
                runtime_messages_match,
                plan_matches,
                binding_matches,
                execution_matches,
                runtime_matches,
            )
        ):
            raise PydanticCustomError(
                FIXTURE_CORRELATION_ERROR, FIXTURE_CORRELATION_MESSAGE
            )
        return self
