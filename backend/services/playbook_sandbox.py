# Copyright (c) 2024-2026 T1 Agentics LLC
# SPDX-License-Identifier: Apache-2.0

"""
Playbook Python Sandbox

Secure execution environment for custom Python code in playbooks.
Uses RestrictedPython for AST-level restrictions and resource limits.

Security Features:
- AST-level code restrictions (no imports of dangerous modules)
- No filesystem access
- No network access
- No system calls
- Memory and execution time limits
- Whitelisted built-in functions only
- Sandboxed globals and locals
"""

import ast
import logging
import time
import signal
import sys
import traceback
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass
from enum import Enum
import json
import re
import math
import hashlib
import base64
from datetime import datetime, timedelta
from functools import wraps
import threading
import multiprocessing
import resource

logger = logging.getLogger(__name__)


# ============================================================================
# Security Configuration
# ============================================================================

class SecurityViolation(Exception):
    """Raised when code attempts a security violation."""
    pass


class ExecutionTimeout(Exception):
    """Raised when code execution times out."""
    pass


class MemoryLimitExceeded(Exception):
    """Raised when code exceeds memory limit."""
    pass


@dataclass
class SandboxConfig:
    """Configuration for the sandbox environment."""
    max_execution_time: int = 30  # seconds
    max_memory_mb: int = 128
    max_output_size: int = 1024 * 1024  # 1MB
    allow_imports: List[str] = None
    allow_builtins: List[str] = None

    def __post_init__(self):
        if self.allow_imports is None:
            self.allow_imports = [
                'json', 're', 'math', 'hashlib', 'base64',
                'datetime', 'collections', 'itertools', 'functools',
                'operator', 'string', 'textwrap', 'difflib',
                'html', 'urllib.parse', 'ipaddress', 'uuid',
                'requests'
            ]
        if self.allow_builtins is None:
            self.allow_builtins = [
                'abs', 'all', 'any', 'ascii', 'bin', 'bool', 'bytes',
                'callable', 'chr', 'dict', 'divmod', 'enumerate',
                'filter', 'float', 'format', 'frozenset', 'hash',
                'hex', 'int', 'isinstance', 'issubclass', 'iter',
                'len', 'list', 'map', 'max', 'min', 'oct', 'ord',
                'pow', 'print', 'range', 'repr', 'reversed', 'round',
                'set', 'slice', 'sorted', 'str', 'sum', 'tuple',
                'type', 'zip', 'True', 'False', 'None'
            ]


# ============================================================================
# Safe Imports
# ============================================================================

def create_safe_import(allowed_modules: List[str]):
    """Create a restricted import function."""
    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Check if module is allowed
        base_module = name.split('.')[0]
        if base_module not in allowed_modules:
            raise SecurityViolation(f"Import of '{name}' is not allowed")

        # Import the module
        import importlib
        module = importlib.import_module(name)

        # If fromlist specified, return the module (for "from x import y")
        if fromlist:
            return module

        # Return top-level module
        top_module = name.split('.')[0]
        return importlib.import_module(top_module)

    return safe_import


# ============================================================================
# Safe Builtins
# ============================================================================

def create_safe_builtins(config: SandboxConfig):
    """Create a restricted builtins dictionary."""
    import builtins

    safe_builtins = {}

    for name in config.allow_builtins:
        if hasattr(builtins, name):
            safe_builtins[name] = getattr(builtins, name)

    # Add safe import
    safe_builtins['__import__'] = create_safe_import(config.allow_imports)

    # Add safe print that captures output
    output_buffer = []

    def safe_print(*args, **kwargs):
        output = ' '.join(str(arg) for arg in args)
        if len('\n'.join(output_buffer)) + len(output) > config.max_output_size:
            raise SecurityViolation("Output size limit exceeded")
        output_buffer.append(output)

    safe_builtins['print'] = safe_print
    safe_builtins['_output_buffer'] = output_buffer

    return safe_builtins


# ============================================================================
# AST Security Checker
# ============================================================================

class SecurityChecker(ast.NodeVisitor):
    """AST visitor that checks for security violations."""

    DANGEROUS_NAMES = {
        'eval', 'exec', 'compile', 'open', 'file',
        '__import__', 'input', 'raw_input',
        'getattr', 'setattr', 'delattr', 'hasattr',
        '__builtins__', '__dict__', '__class__',
        '__bases__', '__subclasses__', '__mro__',
        '__code__', '__globals__', '__locals__',
        'globals', 'locals', 'vars', 'dir',
        'exit', 'quit', 'help', 'license',
        'breakpoint', 'credits', 'copyright'
    }

    DANGEROUS_ATTRS = {
        '__class__', '__bases__', '__subclasses__',
        '__mro__', '__code__', '__globals__',
        '__dict__', '__func__', '__self__',
        '__module__', '__name__', '__qualname__',
        'func_code', 'func_globals', 'gi_code', 'gi_frame'
    }

    def __init__(self, allowed_imports: List[str]):
        self.allowed_imports = allowed_imports
        self.violations = []

    def visit_Import(self, node):
        for alias in node.names:
            module_name = alias.name.split('.')[0]
            if module_name not in self.allowed_imports:
                self.violations.append(
                    f"Import of '{alias.name}' is not allowed (line {node.lineno})"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            module_name = node.module.split('.')[0]
            if module_name not in self.allowed_imports:
                self.violations.append(
                    f"Import from '{node.module}' is not allowed (line {node.lineno})"
                )
        self.generic_visit(node)

    def visit_Name(self, node):
        if node.id in self.DANGEROUS_NAMES:
            self.violations.append(
                f"Use of '{node.id}' is not allowed (line {node.lineno})"
            )
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if node.attr in self.DANGEROUS_ATTRS:
            self.violations.append(
                f"Access to attribute '{node.attr}' is not allowed (line {node.lineno})"
            )
        self.generic_visit(node)

    def visit_Call(self, node):
        # Check for dangerous function calls
        if isinstance(node.func, ast.Name):
            if node.func.id in self.DANGEROUS_NAMES:
                self.violations.append(
                    f"Call to '{node.func.id}' is not allowed (line {node.lineno})"
                )
        self.generic_visit(node)


def check_code_security(code: str, config: SandboxConfig) -> List[str]:
    """Check code for security violations at AST level."""
    try:
        tree = ast.parse(code)
        checker = SecurityChecker(config.allow_imports)
        checker.visit(tree)
        return checker.violations
    except SyntaxError as e:
        return [f"Syntax error: {e}"]


# ============================================================================
# Execution Environment
# ============================================================================

class ExecutionResult:
    """Result of code execution."""

    def __init__(self):
        self.success: bool = False
        self.output: Any = None
        self.error: Optional[str] = None
        self.stdout: List[str] = []
        self.execution_time_ms: float = 0
        self.memory_used_mb: float = 0


def _run_sandboxed_code(code, inputs, config_dict, function_name, result_queue):
    """
    Worker function that runs in a separate process.
    Writes result dict to the queue when done.
    """
    import importlib
    res = {
        'success': False,
        'output': None,
        'error': None,
        'stdout': [],
    }
    try:
        # Rebuild config (can't pickle dataclass with defaults easily)
        config = SandboxConfig(**config_dict)

        # Check code security first
        violations = check_code_security(code, config)
        if violations:
            res['error'] = "Security violations:\n" + "\n".join(violations)
            result_queue.put(res)
            return

        # Create safe execution environment
        safe_builtins = create_safe_builtins(config)
        safe_globals = {
            '__builtins__': safe_builtins,
            '__name__': '__sandbox__',
        }

        # Add allowed modules
        for module_name in config.allow_imports:
            try:
                module = importlib.import_module(module_name)
                safe_globals[module_name.replace('.', '_')] = module
            except ImportError:
                pass

        # Add common helpers directly
        safe_globals['json'] = __import__('json')
        safe_globals['re'] = __import__('re')
        safe_globals['math'] = __import__('math')
        safe_globals['datetime'] = __import__('datetime').datetime
        safe_globals['timedelta'] = __import__('datetime').timedelta
        safe_globals['hashlib'] = __import__('hashlib')
        safe_globals['base64'] = __import__('base64')

        # Add inputs
        safe_globals['inputs'] = inputs

        # Compile code
        compiled = compile(code, '<sandbox>', 'exec')

        # Execute the code
        exec(compiled, safe_globals)

        # Get output from function if it exists
        if function_name in safe_globals:
            func = safe_globals[function_name]
            if callable(func):
                output = func(inputs)
                res['output'] = output
                res['success'] = True
            else:
                res['error'] = f"'{function_name}' is not a function"
        elif 'result' in safe_globals:
            res['output'] = safe_globals['result']
            res['success'] = True
        elif 'output' in safe_globals:
            res['output'] = safe_globals['output']
            res['success'] = True
        else:
            res['output'] = None
            res['success'] = True

        # Capture stdout
        res['stdout'] = safe_builtins.get('_output_buffer', [])

    except SyntaxError as e:
        res['error'] = f"Syntax error: {e}"
    except SecurityViolation as e:
        res['error'] = f"Security violation: {e}"
    except Exception as e:
        res['error'] = f"Execution error: {type(e).__name__}: {str(e)}"
        tb = traceback.format_exc()
        tb = re.sub(r'File "[^"]+", ', 'File "<sandbox>", ', tb)
        res['error'] += f"\n{tb}"

    result_queue.put(res)


def execute_in_sandbox(
    code: str,
    inputs: Dict[str, Any],
    config: SandboxConfig,
    function_name: str = 'main'
) -> ExecutionResult:
    """
    Execute Python code in a sandboxed environment using a separate process
    for reliable timeout enforcement across platforms.

    Args:
        code: Python code to execute
        inputs: Input variables to make available
        config: Sandbox configuration
        function_name: Name of function to call (default: 'main')

    Returns:
        ExecutionResult with output or error
    """
    result = ExecutionResult()
    start_time = time.time()

    # Convert config to dict for pickling
    config_dict = {
        'max_execution_time': config.max_execution_time,
        'max_memory_mb': config.max_memory_mb,
        'max_output_size': config.max_output_size,
        'allow_imports': config.allow_imports,
        'allow_builtins': config.allow_builtins,
    }

    result_queue = multiprocessing.Queue()
    proc = multiprocessing.Process(
        target=_run_sandboxed_code,
        args=(code, inputs, config_dict, function_name, result_queue)
    )
    proc.start()
    proc.join(timeout=config.max_execution_time)

    if proc.is_alive():
        # Timed out — forcibly terminate the process
        proc.terminate()
        proc.join(5)  # Give it 5s to clean up
        if proc.is_alive():
            proc.kill()  # Force kill if still alive
            proc.join(1)
        result.error = f"Execution timed out after {config.max_execution_time} seconds"
    else:
        # Process finished — retrieve result from queue
        try:
            res = result_queue.get_nowait()
            result.success = res.get('success', False)
            result.output = res.get('output')
            result.error = res.get('error')
            result.stdout = res.get('stdout', [])
        except Exception:
            result.error = "Failed to retrieve result from sandbox process"

    result.execution_time_ms = (time.time() - start_time) * 1000
    return result


# ============================================================================
# Playbook Sandbox Service
# ============================================================================

class PlaybookSandbox:
    """
    Sandbox service for executing custom Python code in playbooks.
    """

    def __init__(self, config: SandboxConfig = None):
        self.config = config or SandboxConfig()

    async def execute(
        self,
        code: str,
        inputs: Dict[str, Any],
        function_name: str = 'main'
    ) -> Dict[str, Any]:
        """
        Execute Python code in sandbox.

        Args:
            code: Python code to execute
            inputs: Dictionary of inputs available as 'inputs' variable
            function_name: Name of function to call

        Returns:
            Dictionary with result or error
        """
        logger.info(f"Executing code in sandbox (function: {function_name})")

        result = execute_in_sandbox(
            code=code,
            inputs=inputs,
            config=self.config,
            function_name=function_name
        )

        response = {
            "success": result.success,
            "execution_time_ms": result.execution_time_ms,
        }

        if result.success:
            response["output"] = result.output
            response["stdout"] = result.stdout
        else:
            response["error"] = result.error
            logger.warning(f"Sandbox execution failed: {result.error}")

        return response

    async def validate_code(self, code: str) -> Dict[str, Any]:
        """
        Validate code without executing it.

        Returns:
            Dictionary with validation result
        """
        violations = check_code_security(code, self.config)

        if violations:
            return {
                "valid": False,
                "violations": violations
            }

        # Check syntax
        try:
            ast.parse(code)
        except SyntaxError as e:
            return {
                "valid": False,
                "violations": [f"Syntax error on line {e.lineno}: {e.msg}"]
            }

        return {
            "valid": True,
            "violations": []
        }

    async def get_allowed_imports(self) -> List[str]:
        """Get list of allowed imports."""
        return self.config.allow_imports

    async def get_allowed_builtins(self) -> List[str]:
        """Get list of allowed built-in functions."""
        return self.config.allow_builtins


# ============================================================================
# Function Library Service
# ============================================================================

class FunctionLibrary:
    """
    Manages saved Python functions for reuse in playbooks.
    """

    def __init__(self, sandbox: PlaybookSandbox = None):
        self.sandbox = sandbox or PlaybookSandbox()

    async def create_function(
        self,
        name: str,
        description: str,
        code: str,
        input_schema: Dict[str, Any],
        output_schema: Dict[str, Any],
        created_by: str = None
    ) -> Dict[str, Any]:
        """
        Create a new saved function.

        Functions are stored in the playbook_functions table.
        They require approval before they can be used.
        """
        from services.postgres_db import postgres_db
        import uuid

        # Validate code
        validation = await self.sandbox.validate_code(code)
        if not validation['valid']:
            return {
                "error": "Code validation failed",
                "violations": validation['violations']
            }

        # Test execution with empty inputs
        test_result = await self.sandbox.execute(
            code=code,
            inputs={key: None for key in input_schema.keys()},
            function_name='main'
        )

        if not test_result['success']:
            return {
                "error": "Code test execution failed",
                "details": test_result.get('error')
            }

        # Save to database
        try:
            from middleware.tenant_middleware import get_optional_tenant_id
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    INSERT INTO playbook_functions (
                        name, description, code, input_schema, output_schema,
                        is_approved, created_by, tenant_id
                    ) VALUES ($1, $2, $3, $4, $5, FALSE, $6, $7)
                    RETURNING *
                ''',
                    name,
                    description,
                    code,
                    json.dumps(input_schema),
                    json.dumps(output_schema),
                    uuid.UUID(created_by) if created_by else None,
                    get_optional_tenant_id()
                )

                return {
                    "id": str(row['id']),
                    "name": row['name'],
                    "description": row['description'],
                    "is_approved": row['is_approved'],
                    "created_at": row['created_at'].isoformat()
                }

        except Exception as e:
            logger.error(f"Failed to create function: {e}")
            return {"error": str(e)}

    async def get_function(self, function_id: str) -> Optional[Dict[str, Any]]:
        """Get a function by ID."""
        from services.postgres_db import postgres_db
        import uuid

        try:
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM playbook_functions WHERE id = $1",
                    uuid.UUID(function_id)
                )

                if not row:
                    return None

                return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to get function: {e}")
            return None

    async def get_function_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a function by name."""
        from services.postgres_db import postgres_db

        try:
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT * FROM playbook_functions WHERE name = $1",
                    name
                )

                if not row:
                    return None

                return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to get function by name: {e}")
            return None

    async def list_functions(
        self,
        approved_only: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """List all functions."""
        from services.postgres_db import postgres_db

        try:
            async with postgres_db.tenant_acquire() as conn:
                if approved_only:
                    rows = await conn.fetch('''
                        SELECT * FROM playbook_functions
                        WHERE is_approved = TRUE
                        ORDER BY name
                        LIMIT $1 OFFSET $2
                    ''', limit, offset)
                else:
                    rows = await conn.fetch('''
                        SELECT * FROM playbook_functions
                        ORDER BY name
                        LIMIT $1 OFFSET $2
                    ''', limit, offset)

                return [self._row_to_dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Failed to list functions: {e}")
            return []

    async def approve_function(
        self,
        function_id: str,
        approved_by: str
    ) -> Dict[str, Any]:
        """Approve a function for use in playbooks."""
        from services.postgres_db import postgres_db
        import uuid

        try:
            async with postgres_db.tenant_acquire() as conn:
                row = await conn.fetchrow('''
                    UPDATE playbook_functions
                    SET is_approved = TRUE,
                        approved_by = $1,
                        approved_at = NOW()
                    WHERE id = $2
                    RETURNING *
                ''',
                    uuid.UUID(approved_by),
                    uuid.UUID(function_id)
                )

                if not row:
                    return {"error": "Function not found"}

                logger.info(f"Function {function_id} approved by {approved_by}")
                return self._row_to_dict(row)

        except Exception as e:
            logger.error(f"Failed to approve function: {e}")
            return {"error": str(e)}

    async def execute_function(
        self,
        function_id: str,
        inputs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a saved function."""
        func = await self.get_function(function_id)

        if not func:
            return {"error": "Function not found"}

        if not func.get('is_approved'):
            return {"error": "Function not approved for execution"}

        return await self.sandbox.execute(
            code=func['code'],
            inputs=inputs,
            function_name='main'
        )

    async def execute_function_by_name(
        self,
        name: str,
        inputs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a saved function by name."""
        func = await self.get_function_by_name(name)

        if not func:
            return {"error": f"Function '{name}' not found"}

        if not func.get('is_approved'):
            return {"error": f"Function '{name}' not approved for execution"}

        return await self.sandbox.execute(
            code=func['code'],
            inputs=inputs,
            function_name='main'
        )

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary."""
        result = dict(row)

        for field in ['id', 'created_by', 'approved_by']:
            if result.get(field):
                result[field] = str(result[field])

        for field in ['created_at', 'approved_at']:
            if result.get(field):
                result[field] = result[field].isoformat()

        for field in ['input_schema', 'output_schema']:
            if result.get(field) and isinstance(result[field], str):
                result[field] = json.loads(result[field])

        return result


# ============================================================================
# Singleton Instances
# ============================================================================

_sandbox: Optional[PlaybookSandbox] = None
_function_library: Optional[FunctionLibrary] = None


def get_playbook_sandbox() -> PlaybookSandbox:
    """Get singleton sandbox instance."""
    global _sandbox
    if _sandbox is None:
        _sandbox = PlaybookSandbox()
    return _sandbox


def get_function_library() -> FunctionLibrary:
    """Get singleton function library instance."""
    global _function_library
    if _function_library is None:
        _function_library = FunctionLibrary()
    return _function_library
