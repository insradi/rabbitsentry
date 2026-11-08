# Module contract

The registry in `src/rabbitsentry/modules/__init__.py` is explicit and trusted. Modules are not loaded from customer configuration or downloaded code. Dynamic plugins are deferred.

Each `ModuleSpec` declares ID, version, model version, account/region scope, required operations, check definitions, collector and evaluator. The runner accepts an injected registry for extension tests. Omitted modules generate skipped coverage.

```python
def collect(provider, region) -> list[Collection]:
    # Read through the allowlisted, cached gateway.
    ...


def evaluate(collections, account_id, region, policy, now) -> ModuleOutput:
    # Pure evaluation: no clients, file writes or network access.
    ...
```

`Collection` holds projected observations, time, selector, completion state and a short error code. Never persist full SDK responses. Add deliberate projections for new operations and update the central read policy alongside the allowlist.

`ModuleOutput` carries inventory, check results and additional coverage gaps. Use provider-neutral `ResourceRef` values and stable check IDs. Fingerprints derive from provider, account, region, resource type/identifier and check ID, independent of the run ID. Evidence records collector, operation, time, completeness and JSON-compatible data. Schema 1.0 is the shared boundary; HTML only consumes `Assessment`.

Handle positive, negative, missing-field, incomplete and no-resource cases. Partial evidence can support a positive finding, but not absence across an incomplete collection. Use an explicit scope resource for empty/incomplete inventory. Missing required data must appear as unknown results or additional partial coverage even when a positive finding is also present.

Add synthetic check tests and Botocore Stubber tests for new response contracts/pagination. Tests block socket connections. Run the full suite, formatter and linter; keep the synthetic demo representative of the catalogue.

Future monitoring can reuse resource IDs, evidence, check IDs and versioned results. Scheduling, transport, metrics, durable state and incidents belong in separate components. Batch reports alone do not define a complete monitoring protocol.
