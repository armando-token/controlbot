"""N2 integration tests for LocalHttpModelClient against a loopback mock OpenAI server."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from lab.maintenance_app import create_maintenance_app
from lab.scada_app import create_scada_app
from lab.testing import run_asgi_server
from src.adapters import MappingCredentialProvider, load_facility_config
from src.adapters.sessions import OriginNotAllowedError
from src.contracts.budgets import BudgetConfig
from src.contracts.common import utc_now
from src.contracts.enums import BackendMode, EffectClass, TaskStatus
from src.contracts.models import TaskScope, TaskSpec, ToolSpec
from src.engine.coordinator import Coordinator
from src.engine.tool_registry import ToolRegistry
from src.model import (
    BudgetRemaining,
    LocalHttpModelClient,
    LocalModelConfig,
    ModelProtocolError,
    PromptContext,
    build_model_client,
    validate_local_model_origin,
)
from src.runtime import build_runtime
from src.storage.repo import StorageRepo

_FACILITY_A_PATH = Path("lab/configs/facility_a.json")


def create_mock_openai_server(
    handler: Callable[
        [dict[str, Any], int],
        tuple[int, dict[str, Any] | str, dict[str, str] | None],
    ],
) -> tuple[FastAPI, list[dict[str, Any]]]:
    """Create a loopback OpenAI-compatible /v1/chat/completions mock server."""
    app = FastAPI(title="Mock Local OpenAI Server")
    recorded_requests: list[dict[str, Any]] = []

    @app.get("/v1/models")
    async def list_models() -> JSONResponse:
        return JSONResponse({"object": "list", "data": [{"id": "qwen2.5-7b-instruct"}]})

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        body = await request.json()
        idx = len(recorded_requests)
        recorded_requests.append(
            {"body": body, "headers": dict(request.headers)}
        )
        status_code, payload, extra_headers = handler(body, idx)
        if 300 <= status_code < 400 and extra_headers and "location" in extra_headers:
            return RedirectResponse(url=extra_headers["location"], status_code=status_code)
        if isinstance(payload, str):
            return Response(
                content=payload,
                status_code=status_code,
                media_type="text/plain",
                headers=extra_headers,
            )
        return JSONResponse(content=payload, status_code=status_code, headers=extra_headers)

    return app, recorded_requests


def _dummy_prompt() -> PromptContext:
    return PromptContext(
        task_id="task-http-1",
        run_id="run-http-1",
        depth=0,
        query="Check bomba 34",
        facility_id="facility-a",
        allowed_areas=("area-1",),
    )


def _dummy_budget() -> BudgetRemaining:
    return BudgetRemaining(
        active_children_remaining=2,
        depth_remaining=1,
        tool_calls_remaining=16,
        model_calls_remaining=8,
        wall_seconds_remaining=120.0,
        tokens_remaining=24000,
    )


@pytest.mark.n2
async def test_local_http_tool_call_and_final_with_coordinator_pump34(tmp_path: Path) -> None:
    ref_time = utc_now()
    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        if idx == 0:
            return (
                200,
                {
                    "id": "cmpl-0",
                    "model": "qwen2.5-7b-instruct",
                    "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "Query SCADA alarms",
                                "tool_calls": [
                                    {
                                        "id": "call_1",
                                        "type": "function",
                                        "function": {
                                            "name": "scada.read_alarms",
                                            "arguments": json.dumps(
                                                {"asset": "bomba 34", "area": "area-1"}
                                            ),
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
                None,
            )
        if idx == 1:
            return (
                200,
                {
                    "id": "cmpl-1",
                    "model": "qwen2.5-7b-instruct",
                    "usage": {"prompt_tokens": 60, "completion_tokens": 25, "total_tokens": 85},
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": json.dumps(
                                    {
                                        "decision_type": "tool_call",
                                        "tool_call": {
                                            "tool_id": "maint.read_work_orders",
                                            "args": {"asset": "bomba 34", "area": "area-1"},
                                            "rationale": "Read work orders",
                                        },
                                    }
                                ),
                            },
                        }
                    ],
                },
                None,
            )
        return (
            200,
            {
                "id": "cmpl-2",
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 80, "completion_tokens": 30, "total_tokens": 110},
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "decision_type": "final",
                                    "final_answer": "ALM-3401 and WO-3408 synthesized.",
                                }
                            ),
                        },
                    }
                ],
            },
            None,
        )

    mock_app, recorded = create_mock_openai_server(_handler)
    creds = MappingCredentialProvider(
        {
            ("operator_ro", "p1", "scada"): ("operator_ro", "scada-pass-ro"),
            ("operator_ro", "p1", "maintenance"): ("maint_ro", "maint-pass-ro"),
        }
    )

    async with (
        run_asgi_server(mock_app) as llm_origin,
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        cfg = load_facility_config(
            _FACILITY_A_PATH,
            {"scada": scada_origin, "maintenance": maint_origin},
        )
        llm_cfg = LocalModelConfig(
            origin=llm_origin,
            model_id="qwen2.5-7b-instruct",
            quantization="Q4_K_M",
            prompt_template="chatml-json-tools-v1",
            weights_sha256="deadbeef" * 8,
            strict_model_id_check=True,
        )
        runtime = build_runtime(
            db_path=tmp_path / "http_model.sqlite3",
            profile_root=tmp_path / "profiles",
            facility_config=cfg,
            credential_provider=creds,
            backend_mode=BackendMode.LOCAL_HTTP,
            local_http_config=llm_cfg,
            reference_time_fn=lambda: ref_time,
        )
        async with runtime:
            spec = TaskSpec(
                task_id="task-local-http-pump34",
                user_id="operator_ro",
                profile_id="p1",
                scope=TaskScope(
                    facility_id="facility-a",
                    allowed_origins=(scada_origin, maint_origin),
                    allowed_areas=("area-1",),
                    read_only=True,
                ),
                query="Check bomba 34 alarms and latest maintenance intervention",
                backend_mode=BackendMode.LOCAL_HTTP,
            )
            run = runtime.coordinator.submit_task(spec)
            result = await runtime.coordinator.run_until_settled(run.run_id)

        assert result.status == TaskStatus.SUCCEEDED
        assert "ALM-3401" in result.answer
        assert "WO-3408" in result.answer
        assert result.execution_metrics.usage_estimated is False
        assert result.execution_metrics.prompt_tokens == 190
        assert result.execution_metrics.completion_tokens == 75
        assert result.execution_metrics.total_tokens == 265
        assert len(recorded) == 3
        assert isinstance(runtime.model_client, LocalHttpModelClient)
        assert runtime.model_client.last_response_metadata["quantization"] == "Q4_K_M"
        assert (
            runtime.model_client.last_response_metadata["prompt_template"]
            == "chatml-json-tools-v1"
        )


@pytest.mark.n2
async def test_local_http_omitted_tokens_e09_conservative_fallback(tmp_path: Path) -> None:
    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        usage_block = None if idx == 0 else {"prompt_tokens": None, "completion_tokens": 12}
        resp: dict[str, Any] = {
            "id": f"cmpl-{idx}",
            "model": "qwen2.5-7b-instruct",
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "decision_type": "final",
                                "final_answer": "Conservative token estimation active.",
                            }
                        ),
                    },
                }
            ],
        }
        if usage_block is not None:
            resp["usage"] = usage_block
        return 200, resp, None

    mock_app, _ = create_mock_openai_server(_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        repo = StorageRepo(tmp_path / "e09.sqlite3")
        repo.init_db()
        coord = Coordinator(repo, client, ToolRegistry())
        spec = TaskSpec(
            task_id="task-e09",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Check status",
            backend_mode=BackendMode.LOCAL_HTTP,
        )
        run = coord.submit_task(spec)
        result = await coord.run_until_settled(run.run_id)
        assert result.status == TaskStatus.SUCCEEDED
        assert result.execution_metrics.usage_estimated is True
        assert result.execution_metrics.total_tokens >= (
            result.execution_metrics.prompt_tokens + result.execution_metrics.completion_tokens
        )
        assert result.execution_metrics.prompt_tokens >= 64
        assert result.execution_metrics.completion_tokens >= 32

        # Second call tests partial null usage object
        dec2 = await client.decide(_dummy_prompt(), (), _dummy_budget())
        assert dec2.usage.usage_mode == "estimated"
        assert dec2.usage.prompt_tokens >= 64
        assert dec2.usage.completion_tokens == 12


@pytest.mark.n2
async def test_local_http_delegate_and_request_input_structured_decisions() -> None:
    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        if idx == 0:
            payload = {
                "decision_type": "delegate",
                "delegations": [
                    {
                        "child_label": "scada-branch",
                        "query": "Read alarms",
                        "allowed_tools": ["scada.read_alarms"],
                    }
                ],
            }
        else:
            payload = {
                "decision_type": "request_input",
                "required_action": "Select area-1 or area-2",
            }
        return (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": json.dumps(payload)},
                    }
                ],
            },
            None,
        )

    mock_app, _ = create_mock_openai_server(_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        d1 = await client.decide(_dummy_prompt(), (), _dummy_budget())
        assert d1.decision_type == "delegate"
        assert len(d1.delegations) == 1
        assert d1.delegations[0].child_label == "scada-branch"

        d2 = await client.decide(_dummy_prompt(), (), _dummy_budget())
        assert d2.decision_type == "request_input"
        assert d2.required_action == "Select area-1 or area-2"


@pytest.mark.n2
async def test_local_http_protocol_errors_fail_loudly(tmp_path: Path) -> None:
    responses: list[tuple[int, dict[str, Any] | str]] = [
        (200, "not json at all"),
        (200, {"choices": []}),
        (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {"function": {"name": "scada.read_alarms", "arguments": "{bad"}}
                            ],
                        }
                    }
                ]
            },
        ),
        (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {"function": {"name": "shell.exec", "arguments": "{}"}}
                            ],
                        }
                    }
                ]
            },
        ),
        (
            200,
            {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"decision_type": "final"}),
                        }
                    }
                ]
            },
        ),
        (
            200,
            {
                "usage": {"prompt_tokens": True, "completion_tokens": 5},
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {"decision_type": "final", "final_answer": "ok"}
                            ),
                        }
                    }
                ],
            },
        ),
        (400, {"error": "bad request"}),
    ]

    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any] | str, dict[str, str] | None]:
        del body
        code, payload = responses[idx]
        return code, payload, None

    mock_app, _ = create_mock_openai_server(_handler)
    tools: Sequence[ToolSpec] = ()
    from src.adapters.scada import get_scada_tool_specs

    tools = tuple(get_scada_tool_specs(("http://127.0.0.1:8101",)).values())

    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        for _i in range(len(responses)):
            with pytest.raises(ModelProtocolError, match="."):
                await client.decide(_dummy_prompt(), tools, _dummy_budget())

        # Verify Coordinator settles FAILED (reason="model_error"), never falling back
        repo = StorageRepo(tmp_path / "proto_err.sqlite3")
        repo.init_db()
        responses.append((400, {"error": "bad request"}))
        coord = Coordinator(repo, client, ToolRegistry())
        run = coord.submit_task(
            TaskSpec(
                task_id="task-proto-err",
                user_id="op",
                profile_id="p1",
                scope=TaskScope(facility_id="facility-a", read_only=True),
                query="Check status",
                backend_mode=BackendMode.LOCAL_HTTP,
            )
        )
        res = await coord.run_until_settled(run.run_id)
        assert res.status == TaskStatus.FAILED
        assert repo.get_run(run.run_id).transition_reason == "model_error"


@pytest.mark.n2
async def test_local_http_transient_retry_and_unreachable_server_never_emulates(
    tmp_path: Path,
) -> None:
    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        if idx == 0:
            return 503, {"error": "temporarily busy"}, None
        return (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18},
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {"decision_type": "final", "final_answer": "Recovered on retry."}
                            ),
                        },
                    }
                ],
            },
            None,
        )

    mock_app, _ = create_mock_openai_server(_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        repo = StorageRepo(tmp_path / "retry.sqlite3")
        repo.init_db()
        coord = Coordinator(repo, client, ToolRegistry())
        run = coord.submit_task(
            TaskSpec(
                task_id="task-retry-1",
                user_id="op",
                profile_id="p1",
                scope=TaskScope(facility_id="facility-a", read_only=True),
                query="Retry test",
                backend_mode=BackendMode.LOCAL_HTTP,
                budget=BudgetConfig(max_transient_retries=1),
            )
        )
        res = await coord.run_until_settled(run.run_id)
        assert res.status == TaskStatus.SUCCEEDED
        assert res.execution_metrics.retries == 1

    # Unreachable local port must fail loudly with FAILED, NEVER emulate
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        dead_port = sock.getsockname()[1]
    dead_client = LocalHttpModelClient(
        LocalModelConfig(
            origin=f"http://127.0.0.1:{dead_port}",
            model_id="qwen2.5-7b-instruct",
            timeout_s=1.0,
        )
    )
    repo2 = StorageRepo(tmp_path / "dead.sqlite3")
    repo2.init_db()
    coord2 = Coordinator(repo2, dead_client, ToolRegistry())
    run2 = coord2.submit_task(
        TaskSpec(
            task_id="task-dead-1",
            user_id="op",
            profile_id="p1",
            scope=TaskScope(facility_id="facility-a", read_only=True),
            query="Dead LLM port",
            backend_mode=BackendMode.LOCAL_HTTP,
            budget=BudgetConfig(max_transient_retries=1),
        )
    )
    res2 = await coord2.run_until_settled(run2.run_id)
    assert res2.status == TaskStatus.FAILED
    assert repo2.get_run(run2.run_id).transition_reason == "model_transient_retries_exhausted"

    with pytest.raises(ModelProtocolError, match="silent fallback"):
        build_model_client(BackendMode.LOCAL_HTTP, local_http_config=None)


@pytest.mark.n2
async def test_local_http_origin_allowlist_blocks_external_internet_and_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("https://api.openai.com")
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://8.8.8.8:8080")
    with pytest.raises(OriginNotAllowedError):
        validate_local_model_origin("http://192.168.1.50:8080", allow_private_lan=False)

    assert (
        validate_local_model_origin(
            "http://192.168.1.50:8080",
            allowed_origins=("http://192.168.1.50:8080",),
            allow_private_lan=True,
        )
        == "http://192.168.1.50:8080"
    )

    # Set malicious proxy env vars to prove trust_env=False ignores them
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")

    def _redirect_handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body, idx
        return 302, {}, {"location": "https://evil.example/v1/chat/completions"}

    mock_app, _ = create_mock_openai_server(_redirect_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        with pytest.raises(OriginNotAllowedError, match="Redirect blocked"):
            await client.decide(_dummy_prompt(), (), _dummy_budget())


@pytest.mark.n2
async def test_local_http_empty_tools_rejects_tool_calls_in_both_branches() -> None:
    responses: list[tuple[int, dict[str, Any]]] = [
        (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "tool_calls": [
                                {"function": {"name": "evil.shell", "arguments": "{}"}}
                            ],
                        },
                    }
                ],
            },
        ),
        (
            200,
            {
                "model": "qwen2.5-7b-instruct",
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": json.dumps(
                                {
                                    "decision_type": "tool_call",
                                    "tool_call": {"tool_id": "evil.shell", "args": {}},
                                }
                            ),
                        },
                    }
                ],
            },
        ),
    ]

    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        code, payload = responses[idx]
        return code, payload, None

    mock_app, _ = create_mock_openai_server(_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        for _ in range(2):
            with pytest.raises(ModelProtocolError, match="outside allowed tool list"):
                await client.decide(_dummy_prompt(), (), _dummy_budget())


@pytest.mark.n2
async def test_local_http_propagates_target_origin_and_normalizes_empty_partial_info() -> None:
    tool_spec = ToolSpec(
        tool_id="scada.read_alarms",
        version="1.0.0",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
        allowed_origins=("http://127.0.0.1:8101",),
        effect_class=EffectClass.READ,
        verifier_name="v_scada",
    )
    responses: list[dict[str, Any]] = [
        {
            "model": "qwen2.5-7b-instruct",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "tool_calls": [
                            {
                                "function": {
                                    "name": "scada.read_alarms",
                                    "arguments": json.dumps(
                                        {"asset": "bomba 34", "origin": "http://127.0.0.1:9999"}
                                    ),
                                }
                            }
                        ],
                    },
                }
            ],
        },
        {
            "model": "qwen2.5-7b-instruct",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "decision_type": "tool_call",
                                "tool_call": {
                                    "tool_id": "scada.read_alarms",
                                    "args": {"url": "https://evil.example/alarms"},
                                },
                            }
                        ),
                    },
                }
            ],
        },
        {
            "model": "qwen2.5-7b-instruct",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": json.dumps(
                            {
                                "decision_type": "final",
                                "final_answer": "Done.",
                                "partial_info": {},
                            }
                        ),
                    },
                }
            ],
        },
    ]

    def _handler(
        body: dict[str, Any],
        idx: int,
    ) -> tuple[int, dict[str, Any], dict[str, str] | None]:
        del body
        return 200, responses[idx], None

    mock_app, _ = create_mock_openai_server(_handler)
    async with run_asgi_server(mock_app) as llm_origin:
        client = LocalHttpModelClient(
            LocalModelConfig(origin=llm_origin, model_id="qwen2.5-7b-instruct")
        )
        d1 = await client.decide(_dummy_prompt(), (tool_spec,), _dummy_budget())
        assert d1.tool_call is not None
        assert d1.tool_call.target_origin == "http://127.0.0.1:9999"

        d2 = await client.decide(_dummy_prompt(), (tool_spec,), _dummy_budget())
        assert d2.tool_call is not None
        assert d2.tool_call.target_origin == "https://evil.example"

        d3 = await client.decide(_dummy_prompt(), (tool_spec,), _dummy_budget())
        assert d3.decision_type == "final"
        assert d3.partial_info is None


@pytest.mark.n2
async def test_web_create_app_runtime_env_and_422_origin_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    import httpx
    from src.web.app import create_app

    scada_app = create_scada_app(fixture_mode="default")
    maint_app = create_maintenance_app(fixture_mode="default")
    ref_time = utc_now()
    scada_app.state.scada_state.set_reference_time(ref_time)
    maint_app.state.maintenance_state.set_reference_time(ref_time)

    db_path = tmp_path / "env_web.sqlite3"
    profiles_dir = tmp_path / "profiles"

    async with (
        run_asgi_server(scada_app) as scada_origin,
        run_asgi_server(maint_app) as maint_origin,
    ):
        monkeypatch.setenv("GROKBOT_DB_PATH", str(db_path))
        monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(profiles_dir))
        monkeypatch.setenv("GROKBOT_SCADA_URL", scada_origin)
        monkeypatch.setenv("GROKBOT_MAINTENANCE_URL", maint_origin)

        web_app = create_app()
        assert getattr(web_app.state, "runtime", None) is not None

        async with (
            web_app.router.lifespan_context(web_app),
            run_asgi_server(web_app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
            # External unconfigured origin -> 422 before persisting any row
            bad = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "p1",
                    "facility_id": "facility-a",
                    "allowed_origins": ["https://evil.example"],
                    "query": "Check bomba 34",
                },
            )
            assert bad.status_code == 422
            # Invalid installation_config_path -> 422 before persisting any row
            bad_cfg = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "p1",
                    "facility_id": "facility-a",
                    "installation_config_path": str(tmp_path / "missing_install.yaml"),
                    "query": "Check bomba 34",
                },
            )
            assert bad_cfg.status_code == 422
            conn = sqlite3.connect(db_path)
            try:
                count = conn.execute("SELECT COUNT(*) FROM tasks;").fetchone()[0]
                assert count == 0
            finally:
                conn.close()

            # Valid configured origins -> 201 and settles via real RuntimeCoordinatorAdapter
            good = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "p1",
                    "facility_id": "facility-a",
                    "allowed_origins": [scada_origin, maint_origin],
                    "allowed_areas": ["area-1"],
                    "query": "Check bomba 34",
                },
            )
            assert good.status_code == 201
            run_id = good.json()["run_id"]
            settled = await web_app.state.runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
            assert settled is not None
            assert settled.status == TaskStatus.SUCCEEDED


@pytest.mark.n2
async def test_verifier_unquoted_ambiguity_area2_lab_and_redacted_tracing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import httpx
    from src.adapters.config import load_facility_config
    from src.adapters.verifier import Verifier
    from src.contracts.enums import DataQuality
    from src.contracts.models import Observation, TaskScope, TaskSpec
    from src.contracts.redaction import contains_unredacted_secret
    from src.web.app import create_app

    cfg_a = load_facility_config(Path("lab/configs/facility_a.json"))
    now = utc_now()
    obs1 = Observation(
        source="scada",
        session_id="op__p1__scada",
        asset_id="bomba-34-a1",
        observed_label="bomba 34",
        value="HIGH_VIBRATION",
        unit="alarm_code",
        source_time=now,
        observed_at=now,
        quality=DataQuality.GOOD,
        area="area-1",
    )
    obs2 = Observation(
        source="scada",
        session_id="op__p1__scada",
        asset_id="bomba-34-a2",
        observed_label="bomba 34",
        value="SEAL_LEAK",
        unit="alarm_code",
        source_time=now,
        observed_at=now,
        quality=DataQuality.GOOD,
        area="area-2",
    )
    is_ambig, _, action = Verifier().detect_ambiguity(
        (obs1, obs2), cfg_a, target_asset_query="bomba 34"
    )
    assert is_ambig is True
    assert action is not None
    assert "Ambiguous asset bomba 34 across multiple areas" in action
    assert "'bomba 34'" not in action

    # Area-2 mode returns bomba-77-b2 and accepts SC-77/CMMS-77 filter; facility_b stays SC-77
    scada_area2 = create_scada_app(fixture_mode="area2")
    maint_area2 = create_maintenance_app(fixture_mode="area2")
    assert scada_area2.state.scada_state.get_alarms()[0]["asset_id"] == "bomba-77-b2"
    assert maint_area2.state.maintenance_state.get_work_orders()[0]["asset_id"] == "bomba-77-b2"
    scada_fb = create_scada_app(fixture_mode="facility_b")
    assert scada_fb.state.scada_state.get_alarms()[0]["asset_id"] == "SC-77"

    # Tracing redaction + partial-outage loopback origin pass
    trace_dir = tmp_path / "traces"
    db_path = tmp_path / "trace_web.sqlite3"
    profiles_dir = tmp_path / "profiles"
    async with run_asgi_server(create_scada_app(fixture_mode="default")) as scada_origin:
        monkeypatch.setenv("GROKBOT_DB_PATH", str(db_path))
        monkeypatch.setenv("GROKBOT_PROFILE_ROOT", str(profiles_dir))
        monkeypatch.setenv("GROKBOT_SCADA_URL", scada_origin)
        monkeypatch.delenv("GROKBOT_MAINTENANCE_URL", raising=False)
        monkeypatch.delenv("GROKBOT_INSTALLATION_CONFIG", raising=False)
        monkeypatch.setenv("GROKBOT_TRACING_ENABLED", "1")
        monkeypatch.setenv("GROKBOT_TRACE_DIR", str(trace_dir))

        web_app = create_app()
        async with (
            web_app.router.lifespan_context(web_app),
            run_asgi_server(web_app) as web_origin,
            httpx.AsyncClient(base_url=web_origin, trust_env=False) as client,
        ):
            resp = await client.post(
                "/api/tasks",
                json={
                    "user_id": "operator_ro",
                    "profile_id": "p1",
                    "facility_id": "facility-a",
                    "allowed_origins": [scada_origin, "http://127.0.0.1:59999"],
                    "allowed_areas": ["area-1"],
                    "query": (
                        "Check bomba 34 password=secret-pw-123 "
                        "Authorization: Bearer secret-tok-123"
                    ),
                },
            )
            assert resp.status_code == 201
            run_id = resp.json()["run_id"]
            settled = await web_app.state.runtime.web_coordinator.wait_for_run(run_id, timeout=20.0)
            assert settled is not None
            assert settled.status == TaskStatus.PARTIAL
            snap_resp = await client.get(f"/api/tasks/{run_id}")
            assert snap_resp.status_code == 200

    trace_files = list(trace_dir.glob("trace_*.json"))
    assert trace_files
    trace_text = trace_files[0].read_text(encoding="utf-8")
    assert "secret-pw-123" not in trace_text
    assert "secret-tok-123" not in trace_text
    assert not contains_unredacted_secret(trace_text)
    assert not contains_unredacted_secret(json.loads(trace_text))
    del TaskScope, TaskSpec
