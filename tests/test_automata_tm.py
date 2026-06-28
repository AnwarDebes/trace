import numpy as np
import pytest
from tracekit import ETTABank, TsetlinMachine, TMConfig, to_literals


def test_vanilla_equivalence_seed_locked():
    """lambda=0, alpha=0 -> trace stays identically zero (vanilla TA)."""
    bank = ETTABank(n_clauses=8, n_literals=10, lambda_decay=0.0, trace_alpha=0.0,
                    rng=np.random.default_rng(0))
    lits = np.array([1, 0, 1, 1, 0, 0, 1, 0, 1, 0], dtype=np.int8)
    co = bank.clause_outputs(lits)
    bank.type_I_feedback(co, lits, s=3.9)
    bank.type_II_feedback(co, lits)
    assert np.all(bank.trace == 0.0)


def test_trace_accumulates_when_enabled():
    bank = ETTABank(n_clauses=4, n_literals=6, lambda_decay=0.5, trace_alpha=1.0,
                    rng=np.random.default_rng(1))
    lits = np.ones(6, dtype=np.int8)
    co = bank.clause_outputs(lits)
    for _ in range(3):
        bank.type_I_feedback(co, lits, s=2.0)
    assert bank.trace.max() > 0.0
    assert bank.trace.max() <= 1.0


def test_clause_output_and_semantics():
    bank = ETTABank(n_clauses=1, n_literals=4)
    bank.state[0, 0] = bank.N + 1   # include literal 0
    bank.state[0, 2] = bank.N + 1   # include literal 2
    assert bank.clause_outputs(np.array([1, 0, 1, 0]))[0] == 1
    assert bank.clause_outputs(np.array([1, 0, 0, 0]))[0] == 0   # literal 2 = 0


def test_predict_empty_clause_zero():
    bank = ETTABank(n_clauses=1, n_literals=4)   # all-exclude
    assert bank.clause_outputs(np.array([1, 1, 1, 1]), predict=True)[0] == 0
    assert bank.clause_outputs(np.array([1, 1, 1, 1]), predict=False)[0] == 1


def test_to_literals_roundtrip():
    X = np.array([[1, 0, 1]], dtype=np.int8)
    L = to_literals(X)
    assert L.tolist() == [[1, 0, 1, 0, 1, 0]]


def test_to_literals_rejects_non_binary():
    with pytest.raises(ValueError):
        to_literals(np.array([[2, 0]]))


def test_tm_learns_xor():
    rng = np.random.default_rng(0)
    X = rng.integers(0, 2, size=(400, 2)).astype(np.int8)
    y = (X[:, 0] ^ X[:, 1]).astype(np.int8)
    tm = TsetlinMachine(TMConfig(n_clauses=20, n_features=2, threshold=10, s=3.0, seed=1))
    tm.fit(X, y, epochs=30)
    assert tm.score(X, y) > 0.95


def test_tm_requires_even_clauses():
    with pytest.raises(ValueError):
        TsetlinMachine(TMConfig(n_clauses=5, n_features=2))
