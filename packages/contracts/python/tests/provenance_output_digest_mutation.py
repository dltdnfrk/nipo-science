from science_workbench_contracts.dry_lab_contract import DryLabRunContract


def output_mutation(
    contract: DryLabRunContract,
    tamper_hash: str,
) -> DryLabRunContract:
    output_id = contract.outputs.normalized_csv_version_id
    versions = tuple(
        version.model_copy(update={"content_sha256": tamper_hash})
        if version.id == output_id
        else version
        for version in contract.artifact_versions
    )
    rows = tuple(
        row.model_copy(update={"supporting_sha256": tamper_hash})
        if row.artifact_version_id == output_id
        else row
        for row in contract.ledger.rows
    )
    pins = tuple(
        pin.model_copy(update={"sha256": tamper_hash})
        if pin.ref_id == str(output_id)
        else pin
        for pin in contract.provenance.output_hashes
    )
    entries = tuple(
        entry.model_copy(update={"sha256": tamper_hash})
        if entry.artifact_version_id == output_id
        else entry
        for entry in contract.export.artifact_entries
    )
    return contract.model_copy(
        update={
            "artifact_versions": versions,
            "ledger": contract.ledger.model_copy(update={"rows": rows}),
            "provenance": contract.provenance.model_copy(
                update={"output_hashes": pins}
            ),
            "export": contract.export.model_copy(update={"artifact_entries": entries}),
        }
    )
