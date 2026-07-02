from typing import Any, override
import re

from e2b_code_interpreter import Sandbox

from aci.common.db.sql_models import LinkedAccount
from aci.common.exceptions import AppConnectorError
from aci.common.logging_setup import get_logger
from aci.common.schemas.security_scheme import (
    APIKeyScheme,
    APIKeySchemeCredentials,
)
from aci.server.app_connectors.base import AppConnectorBase

logger = get_logger(__name__)

# Default resource limits
DEFAULT_EXECUTION_TIMEOUT = 30  # seconds
DEFAULT_OUTPUT_SIZE_LIMIT = 10 * 1024  # 10KB

# Dangerous import patterns to block
_BLOCKED_IMPORT_PATTERNS = [
    re.compile(r"^\s*import\s+os\b", re.MULTILINE),
    re.compile(r"^\s*import\s+subprocess\b", re.MULTILINE),
    re.compile(r"^\s*import\s+socket\b", re.MULTILINE),
    re.compile(r"^\s*from\s+os\s+import\b", re.MULTILINE),
    re.compile(r"^\s*from\s+subprocess\s+import\b", re.MULTILINE),
    re.compile(r"^\s*from\s+socket\s+import\b", re.MULTILINE),
]


class E2b(AppConnectorBase):
    """
    E2B.dev Sandbox Connector using Code Interpreter.
    """

    def __init__(
        self,
        linked_account: LinkedAccount,
        security_scheme: APIKeyScheme,
        security_credentials: APIKeySchemeCredentials,
    ):
        super().__init__(linked_account, security_scheme, security_credentials)
        self.api_key = security_credentials.secret_key

    @override
    def _before_execute(self) -> None:
        pass

    def run_code(
        self,
        code: str,
        timeout: int = DEFAULT_EXECUTION_TIMEOUT,
        output_size_limit: int = DEFAULT_OUTPUT_SIZE_LIMIT,
    ) -> dict[str, Any]:
        """
        Execute code in E2B sandbox and return the result.
        """
        # Validate code for dangerous imports
        for pattern in _BLOCKED_IMPORT_PATTERNS:
            if pattern.search(code):
                raise AppConnectorError(
                    message="Code contains blocked import (os/subprocess/socket). "
                    "These modules are not allowed for security reasons."
                )

        with Sandbox(api_key=self.api_key) as sandbox:
            execution = sandbox.run_code(code, timeout=timeout)
            result_text = execution.text or ""
            # Truncate output if it exceeds size limit
            if len(result_text) > output_size_limit:
                result_text = result_text[:output_size_limit] + "\n... [output truncated]"
            return {"text": result_text}
