from .artifacts import ArtifactVersion
from .auth import AuthContext
from .common import ContractModel
from .runs import Run


class ContractRoundTrip(ContractModel):
    auth: AuthContext
    run: Run
    artifact_version: ArtifactVersion
