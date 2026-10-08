"""Record each gate step's failure in the module's result table."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: Any, call: Any) -> Iterator[None]:
    outcome = yield
    report = outcome.get_result()
    match = re.match(r"test_(\d\d)_", item.name)
    results = getattr(item.module, "RESULTS", None)
    if match and results is not None and report.when == "call" and report.failed:
        results[match.group(1)] = ("FAIL", str(call.excinfo.value).splitlines()[0][:300])
