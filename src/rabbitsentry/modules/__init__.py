"""Explicit registry of trusted bundled modules; no dynamic code loading."""

from . import compute, database, iam, network

REGISTRY = {spec.id: spec for spec in (iam.SPEC, network.SPEC, compute.SPEC, database.SPEC)}
