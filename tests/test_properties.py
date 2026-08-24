import pytest

from logfable.engine import GenerationConfig, generate
from logfable.scenarios import load_scenario

hypothesis = pytest.importorskip("hypothesis")
st = pytest.importorskip("hypothesis.strategies")
given = hypothesis.given


@given(st.integers(min_value=1, max_value=2**31 - 1), st.integers(min_value=1, max_value=100))
def test_seeded_generation_has_unique_ids(seed, users):
    cfg = GenerationConfig(
        duration_seconds=300,
        users=users,
        noise=80,
        seed=seed,
        preset="small-business",
        target_events=30,
    )
    events, *_ = generate(load_scenario("password-spray-account-takeover"), cfg)
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids))
