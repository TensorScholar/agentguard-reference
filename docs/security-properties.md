# Security properties and test map

This map names assertions in the current suite, not results of a test run. Paths are relative to the package root; each method belongs to the class shown. Tests support unittest discovery and pytest.

| Property | Test path and methods |
|---|---|
| Exact action binding | `tests/unit/test_guard.py`: `GuardTests.test_changed_action_fields_deny`; `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_local_argument_mutation_denied`, `ScenarioTests.test_synthetic_privilege_and_audience_changes_denied` |
| Nested snapshot isolation | `tests/unit/test_guard.py`: `GuardTests.test_action_canonical_snapshot`; `tests/security/test_boundaries.py`: `BoundaryTests.test_mutable_original_and_callback_cannot_change_authorized_snapshot` |
| Strict JSON and identities | `tests/unit/test_guard.py`: `GuardTests.test_bool_float_and_non_json_arguments_rejected`, `GuardTests.test_nonstring_identities_rejected`, `GuardTests.test_malformed_noncanonical_and_nonobject_json_rejected`, `GuardTests.test_depth_boundary`, `GuardTests.test_argument_size_and_container_limits` |
| Policy types and amount boundaries | `tests/unit/test_guard.py`: `GuardTests.test_policy_invalid_limits`, `GuardTests.test_policy_requires_immutable_valid_actions`, `GuardTests.test_policy_empty_actions_denies`, `GuardTests.test_amount_zero_negative_over_ceiling_missing_and_nonstrict_types`, `GuardTests.test_amount_at_ceiling_executes` |
| Current-policy binding | `tests/unit/test_guard.py`: `GuardTests.test_changed_policy_same_revision_denies` |
| Authorization authenticity | `tests/unit/test_guard.py`: `GuardTests.test_wrong_key_and_signature_deny`; `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_invalid_authorizations_denied` |
| Lifetime, including exact expiry denial | `tests/unit/test_guard.py`: `GuardTests.test_ttl_is_bound_to_issuance`, `GuardTests.test_exact_expiry_and_after_expiry_deny`, `GuardTests.test_before_issuance_denies`, `GuardTests.test_invalid_clock_fails_issuance_and_execution` |
| Sequential and concurrent single-use dispatch | `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_local_replay_denied`; `tests/security/test_boundaries.py`: `BoundaryTests.test_replay_sixteen_threads_single_winner`, `BoundaryTests.test_admission_samples_clock_inside_claim`, `BoundaryTests.test_rejected_claim_does_not_consume`; `tests/unit/test_guard.py`: `GuardTests.test_duplicate_nonce_second_ticket_is_replay` |
| Expiry does not consume the ticket | `tests/unit/test_guard.py`: `GuardTests.test_expiry_does_not_consume_authorization` |
| Policy revision change | `tests/unit/test_guard.py`: `GuardTests.test_policy_revision_change_denies` |
| Guard configuration and nonce identity | `tests/unit/test_guard.py`: `GuardTests.test_guard_rejects_invalid_configuration`, `GuardTests.test_padded_nonce_fails_issuance` |
| Callback interruption retains consumption | `tests/unit/test_guard.py`: `GuardTests.test_keyboardinterrupt_records_unknown_and_consumes` |
| Callback failure retains consumption | `tests/unit/test_guard.py`: `GuardTests.test_unknown_callback_outcome_retains_replay` |
| Authorization audit fails closed | `tests/security/test_boundaries.py`: `BoundaryTests.test_authorization_audit_failure_withholds_authorization` |
| Admission audit fails closed and retains consumption | `tests/security/test_boundaries.py`: `BoundaryTests.test_admission_audit_failure_denies_and_retains_replay` |
| Honest outcome audit failure reporting | `tests/security/test_boundaries.py`: `BoundaryTests.test_success_outcome_audit_failure_is_unknown_and_consumed`, `BoundaryTests.test_exception_outcome_audit_failure_is_unknown_and_consumed` |
| Caller-asserted provenance enforcement, not prompt classification | `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_untrusted_provenance_denied`, `ScenarioTests.test_synthetic_provenance_mutation_after_authorization_denied`, `ScenarioTests.test_synthetic_principal_mismatch_is_action_mismatch` |
| Audit integrity and schema | `tests/unit/test_audit.py`: `AuditTests.test_wrong_key`, `AuditTests.test_tamper_each_field`, `AuditTests.test_reorder_and_remove_middle`, `AuditTests.test_strict_schema_rejects_missing_and_extra_fields`, `AuditTests.test_malformed_values_even_with_valid_mac`, `AuditTests.test_invalid_keys_rejected_even_for_empty_chain`, `AuditTests.test_authorization_domain_separator_is_not_audit_mac` |
| Trusted endpoint anchoring | `tests/unit/test_audit.py`: `AuditTests.test_valid_chain_and_expected_head`, `AuditTests.test_prefix_removal_fails`, `AuditTests.test_suffix_removal_requires_trusted_head` |
| Audit avoids raw principal, arguments, and exception text | `tests/security/test_boundaries.py`: `BoundaryTests.test_audit_contains_no_raw_arguments_principal_or_exception` |
| Deterministic CLI demo and failure status | `tests/unit/test_cli.py`: `CliTests.test_demo_repeated_is_deterministic`, `CliTests.test_demo_failure_exit_status` |
| External verification key and head | `tests/unit/test_cli.py`: `CliTests.test_verify_valid_array_and_document_external_key_and_head`, `CliTests.test_verify_wrong_key_and_head`, `CliTests.test_embedded_key_cannot_override_external_key` |
| CLI tamper and malformed input handling | `tests/unit/test_cli.py`: `CliTests.test_verify_tampered_and_missing_record_fields`, `CliTests.test_verify_missing_records_and_invalid_document_shapes`, `CliTests.test_verify_malformed_json`, `CliTests.test_verify_unreadable_files` |
| CLI file-size caps | `tests/unit/test_cli.py`: `CliTests.test_verify_size_caps_reject_before_reading`, `CliTests.test_verify_size_caps_are_inclusive` |
| Required CLI options and process exit propagation | `tests/unit/test_cli.py`: `CliTests.test_verify_requires_external_key_file_and_expected_head`, `CliTests.test_module_propagates_cli_exit_status` |

## Interpreting coverage

Denied-path guard tests assert that the executor was not called. Single-use tests count callback invocations; audit-failure tests distinguish pre-dispatch denial from post-dispatch uncertainty. CLI tests mock `Path.stat`, `Path.read_text`, and `Path.read_bytes` and capture output without creating input files. Size-cap tests exercise reported stat sizes, not allocation of large files.

Action arguments use canonical ASCII JSON of at most 65536 characters, maximum depth 16 with the root at depth 0, and at most 1024 entries per container. Identity strings are nonblank and at most 256 characters. The depth test exercises both sides of its boundary; size/container tests exercise over-limit rejection. This map does not imply exhaustive boundary coverage for every bound.

## Limits on the claims

- Principal and provenance are asserted by the trusted caller; refund policy is not identity authentication and does not classify prompts.
- Deterministic clocks and nonce factories are test controls, not deployment trust mechanisms. Exact expiry denies execution: `issued_at <= now < expires_at`.
- Shared-store thread tests do not establish cross-process or restart safety.
- HMAC key holders can forge records; the public demo key provides no adversarial authenticity.
- A valid chain without a trusted expected endpoint does not establish completeness.
- Callback return does not establish an external business effect or production readiness.

Commands and reporting requirements are in [reproducibility](reproducibility.md).
