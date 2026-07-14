from collections.abc import Iterable
from threading import Lock
from typing import final, override

from .approval import (
    ApprovalConsumeCommand,
    ApprovalConsumptionStore,
    ApprovalProtocolError,
    validated_approval_consumption,
)
from .models import ApprovalRecord


@final
class InMemoryApprovalConsumptionStore(ApprovalConsumptionStore):
    def __init__(self, approvals: Iterable[ApprovalRecord]) -> None:
        records = tuple(approvals)
        self._records = {approval.id: approval for approval in records}
        if len(self._records) != len(records):
            raise ApprovalProtocolError(code="APPROVAL_DUPLICATE_ID")
        self._consumed_digests = {
            approval.digest for approval in records if approval.status == "consumed"
        }
        self._consumed_bindings = {
            approval.binding.model_dump_json()
            for approval in records
            if approval.status == "consumed"
        }
        self._lock = Lock()

    @override
    def compare_and_consume(self, command: ApprovalConsumeCommand) -> ApprovalRecord:
        with self._lock:
            approval = self._records.get(command.approval_id)
            if approval is None:
                raise ApprovalProtocolError(code="APPROVAL_ID_MISMATCH")
            consumed = validated_approval_consumption(approval, command)
            binding_key = consumed.binding.model_dump_json()
            if (
                consumed.digest in self._consumed_digests
                or binding_key in self._consumed_bindings
            ):
                raise ApprovalProtocolError(code="APPROVAL_ALREADY_CONSUMED")
            self._records[approval.id] = consumed
            self._consumed_digests.add(consumed.digest)
            self._consumed_bindings.add(binding_key)
            return consumed
