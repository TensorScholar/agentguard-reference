# Security properties and test map

This document is the boundary between what the package claims and what the suite actually asserts. It exists so that a reader never has to take a claim on trust, and so that a claim cannot quietly outlive the test that backs it.

## Property classes and test map

This map names assertions in the current suite, not results of a test run. Paths are relative to the package root; each method belongs to the class shown. Tests support unittest discovery and pytest. Every test method in the suite appears in exactly one row below.

The limits section states what these rows do not establish. Read it before treating any row as a guarantee.

### Action integrity

| Property | Test path and methods |
|---|---|
| Exact action binding | `tests/unit/test_guard.py`: `GuardTests.test_changed_action_fields_deny`; `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_local_argument_mutation_denied`, `ScenarioTests.test_synthetic_privilege_and_audience_changes_denied` |
| Nested snapshot isolation | `tests/unit/test_guard.py`: `GuardTests.test_action_canonical_snapshot`; `tests/security/test_boundaries.py`: `BoundaryTests.test_mutable_original_and_callback_cannot_change_authorized_snapshot` |
| Strict JSON and identities | `tests/unit/test_guard.py`: `GuardTests.test_bool_float_and_non_json_arguments_rejected`, `GuardTests.test_nonstring_identities_rejected`, `GuardTests.test_malformed_noncanonical_and_nonobject_json_rejected`, `GuardTests.test_depth_boundary`, `GuardTests.test_argument_size_and_container_limits` |
| Canonicalisation is injective on accepted values | `tests/unit/test_canonical.py`: `CanonicalisationTests.test_distinct_scalar_values_do_not_collapse`, `CanonicalisationTests.test_distinct_nested_values_do_not_collapse`, `CanonicalisationTests.test_key_order_does_not_change_the_snapshot`, `CanonicalisationTests.test_non_ascii_has_one_canonical_escaped_form`, `CanonicalisationTests.test_digest_is_a_pure_function_of_the_canonical_form`, `CanonicalisationTests.test_rejected_values_never_reach_a_snapshot`, `CanonicalisationTests.test_float_bearing_text_is_rejected_at_construction` |
| Caller-asserted provenance, not prompt classification, and defeatable by omission | `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_asserted_untrusted_flag_is_honoured_when_set`, `ScenarioTests.test_synthetic_asserted_untrusted_flag_is_defeatable_by_omission`, `ScenarioTests.test_synthetic_untrusted_flag_mutation_after_authorization_denied`, `ScenarioTests.test_synthetic_principal_mismatch_is_action_mismatch` |

### Policy and configuration binding

| Property | Test path and methods |
|---|---|
| Policy types and amount boundaries | `tests/unit/test_guard.py`: `GuardTests.test_policy_invalid_limits`, `GuardTests.test_policy_requires_immutable_valid_actions`, `GuardTests.test_policy_empty_actions_denies`, `GuardTests.test_amount_zero_negative_over_ceiling_missing_and_nonstrict_types`, `GuardTests.test_amount_at_ceiling_executes` |
| Current-policy binding | `tests/unit/test_guard.py`: `GuardTests.test_changed_policy_same_revision_denies` |
| Policy revision change | `tests/unit/test_guard.py`: `GuardTests.test_policy_revision_change_denies` |

### Ticket lifetime and authenticity

| Property | Test path and methods |
|---|---|
| Lifetime, including exact expiry denial | `tests/unit/test_guard.py`: `GuardTests.test_ttl_is_bound_to_issuance`, `GuardTests.test_exact_expiry_and_after_expiry_deny`, `GuardTests.test_before_issuance_denies`, `GuardTests.test_invalid_clock_fails_issuance_and_execution` |
| Expiry does not consume the ticket | `tests/unit/test_guard.py`: `GuardTests.test_expiry_does_not_consume_authorization` |
| Authorization authenticity | `tests/unit/test_guard.py`: `GuardTests.test_wrong_key_and_signature_deny`; `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_invalid_authorizations_denied` |
| Guard configuration and nonce identity | `tests/unit/test_guard.py`: `GuardTests.test_guard_rejects_invalid_configuration`, `GuardTests.test_padded_nonce_fails_issuance` |

### Single-use dispatch

| Property | Test path and methods |
|---|---|
| Sequential and concurrent single-use dispatch | `tests/adversarial/test_scenarios.py`: `ScenarioTests.test_synthetic_local_replay_denied`; `tests/security/test_boundaries.py`: `BoundaryTests.test_replay_sixteen_threads_single_winner`, `BoundaryTests.test_admission_samples_clock_inside_claim`, `BoundaryTests.test_rejected_claim_does_not_consume`; `tests/unit/test_guard.py`: `GuardTests.test_duplicate_nonce_second_ticket_is_replay` |
| Named hazards: cross-store replay, independent store copies, non-reentrant store lock, unbounded growth | `tests/security/test_hazards.py`: `CrossStoreReplayTests.test_h1_consumed_ticket_is_replayable_through_a_second_store`, `CrossStoreReplayTests.test_h1_single_use_still_holds_within_one_store`, `CrossStoreReplayTests.test_h2_independent_store_copies_admit_the_same_ticket`, `StoreLockTests.test_h3_store_lock_is_not_reentrant`, `UnboundedGrowthTests.test_h4_denied_authorize_traffic_grows_the_audit_log`, `UnboundedGrowthTests.test_h4_consumed_ids_and_records_never_shrink`, `UnboundedGrowthTests.test_h4_audit_log_has_no_bound_or_eviction_api` |

### Fail-closed audit gates and outcome honesty

| Property | Test path and methods |
|---|---|
| Authorization audit fails closed | `tests/security/test_boundaries.py`: `BoundaryTests.test_authorization_audit_failure_withholds_authorization` |
| Admission audit fails closed and retains consumption | `tests/security/test_boundaries.py`: `BoundaryTests.test_admission_audit_failure_denies_and_retains_replay` |
| Honest outcome audit failure reporting | `tests/security/test_boundaries.py`: `BoundaryTests.test_success_outcome_audit_failure_is_unknown_and_consumed`, `BoundaryTests.test_exception_outcome_audit_failure_is_unknown_and_consumed` |
| Callback interruption retains consumption | `tests/unit/test_guard.py`: `GuardTests.test_keyboardinterrupt_records_unknown_and_consumes` |
| Callback failure retains consumption | `tests/unit/test_guard.py`: `GuardTests.test_unknown_callback_outcome_retains_replay` |
| Fail-closed denial auditing and invalid inputs | `tests/security/test_boundaries.py`: `BoundaryTests.test_denial_audit_failure_still_never_calls_executor`, `BoundaryTests.test_action_constructor_rejects_invalid_input`; `tests/unit/test_guard.py`: `GuardTests.test_invalid_action_and_authorization_fail_closed`, `GuardTests.test_noncallable_denies_without_consuming_authorization`, `GuardTests.test_raising_clock_fails_closed` |
| Audit avoids raw principal, arguments, and exception text | `tests/security/test_boundaries.py`: `BoundaryTests.test_audit_contains_no_raw_arguments_principal_or_exception` |

### Audit chain integrity and evidence

| Property | Test path and methods |
|---|---|
| Audit integrity and schema | `tests/unit/test_audit.py`: `AuditTests.test_wrong_key`, `AuditTests.test_tamper_each_field`, `AuditTests.test_reorder_and_remove_middle`, `AuditTests.test_strict_schema_rejects_missing_and_extra_fields`, `AuditTests.test_malformed_values_even_with_valid_mac`, `AuditTests.test_invalid_keys_rejected_even_for_empty_chain`, `AuditTests.test_authorization_domain_separator_is_not_audit_mac` |
| Trusted endpoint anchoring | `tests/unit/test_audit.py`: `AuditTests.test_valid_chain_and_expected_head`, `AuditTests.test_prefix_removal_fails`, `AuditTests.test_suffix_removal_requires_trusted_head` |
| Audit log integrity under malformed and adversarial inputs | `tests/unit/test_audit.py`: `AuditTests.test_malformed_macs`, `AuditTests.test_malformed_record_collections`, `AuditTests.test_invalid_expected_heads`, `AuditTests.test_empty_chain`, `AuditTests.test_snapshot_isolation`, `AuditTests.test_invalid_append_does_not_change_chain`, `AuditTests.test_concurrent_appends_form_one_chain` |
| Prefix integrity has an explicit weak-mode name | `tests/unit/test_audit.py`: `AuditTests.test_verify_prefix_is_the_named_weak_mode`, `AuditTests.test_verify_prefix_is_exported` |

### CLI verification trust inputs

| Property | Test path and methods |
|---|---|
| External verification key and head | `tests/unit/test_cli.py`: `CliTests.test_verify_valid_array_and_document_external_key_and_head`, `CliTests.test_verify_wrong_key_and_head`, `CliTests.test_embedded_key_cannot_override_external_key` |
| CLI tamper and malformed input handling | `tests/unit/test_cli.py`: `CliTests.test_verify_tampered_and_missing_record_fields`, `CliTests.test_verify_missing_records_and_invalid_document_shapes`, `CliTests.test_verify_malformed_json`, `CliTests.test_verify_unreadable_files` |
| CLI file-size caps | `tests/unit/test_cli.py`: `CliTests.test_verify_size_caps_reject_before_reading`, `CliTests.test_verify_size_caps_are_inclusive` |
| Required CLI options and process exit propagation | `tests/unit/test_cli.py`: `CliTests.test_verify_requires_external_key_file_and_expected_head`, `CliTests.test_module_propagates_cli_exit_status` |

### Guided demo

| Property | Test path and methods |
|---|---|
| Guided demo demonstrates all five properties | `tests/unit/test_cli.py`: `CliTests.test_demo_documents_every_required_property`, `CliTests.test_demo_narrates_each_property_and_states_it_is_not_core` |
| Deterministic demo output and exit status | `tests/unit/test_cli.py`: `CliTests.test_demo_repeated_is_deterministic`, `CliTests.test_demo_failure_exit_status`, `CliTests.test_demo_json_and_narrative_are_both_deterministic`, `CliTests.test_no_argument_invocation_runs_the_guided_demo`, `CliTests.test_demo_never_claims_a_bare_verification_result` |

### Publication and packaging

| Property | Test path and methods |
|---|---|
| Version identity is single-sourced and drift is caught | `tests/unit/test_identity.py`: `VersionIdentityTests.test_package_version_is_the_declared_value`, `VersionIdentityTests.test_pyproject_version_is_not_hardcoded`, `VersionIdentityTests.test_pyproject_reads_version_from_the_package`, `VersionIdentityTests.test_installed_distribution_metadata_matches_the_package`, `VersionIdentityTests.test_changelog_records_the_withdrawn_numbering`, `VersionIdentityTests.test_no_dead_public_api_remains` |
| Honest public metadata | `tests/unit/test_identity.py`: `VersionIdentityTests.test_public_metadata_states_the_package_is_not_core`, `VersionIdentityTests.test_public_metadata_declares_typing_and_licence_terms`, `VersionIdentityTests.test_package_ships_a_typing_marker`, `VersionIdentityTests.test_license_names_a_real_copyright_holder`, `VersionIdentityTests.test_readme_states_the_core_relationship_on_the_first_screen`, `VersionIdentityTests.test_security_policy_states_the_core_relationship` |
| Publishable inventory and content policy | `tests/unit/test_release.py`: `ReleaseCollectorTests.test_source_inventory_excludes_generated_and_private_material`, `ReleaseCollectorTests.test_collector_does_not_archive_its_own_exclusion_logic`, `ReleaseCollectorTests.test_collector_rejects_unapproved_file_types`, `ReleaseCollectorTests.test_build_writes_the_declared_artifact_set`, `PublicArtifactPolicyTests.test_every_publishable_file_satisfies_the_policy`, `PublicArtifactPolicyTests.test_policy_accepts_this_packages_public_names`, `PublicArtifactPolicyTests.test_stem_is_derived_from_the_declared_distribution_name` |
## Interpreting coverage

Denied-path guard tests assert that the executor was not called. Single-use tests count callback invocations; audit-failure tests distinguish pre-dispatch denial from post-dispatch uncertainty. CLI tests mock `Path.stat`, `Path.read_text`, and `Path.read_bytes` and capture output without creating input files. Size-cap tests exercise reported stat sizes, not allocation of large files.

Action arguments use canonical ASCII JSON of at most 65536 characters, maximum depth 16 with the root at depth 0, and at most 1024 entries per container. Identity strings are nonblank and at most 256 characters. The depth test exercises both sides of its boundary; size/container tests exercise over-limit rejection. This map does not imply exhaustive boundary coverage for every bound.

## Limits on the claims

**The executor is trusted process code, and argument binding is a record property rather than an enforcement boundary.** Every row above assumes a caller that routes work through the guard and an executor it trusts. Stated in full in [the threat model](threat-model.md) and [limitations](limitations.md).

- Principal and provenance are asserted by the trusted caller; refund policy is not identity authentication and does not classify prompts. The `untrusted` field is a caller assertion **inside the arguments the caller supplies** and is defeated by omitting it.
- Deterministic clocks and nonce factories are test controls, not deployment trust mechanisms. Exact expiry denies execution: `issued_at <= now < expires_at`.
- Single-use state belongs to a store, not to a ticket. A ticket consumed in one store can be dispatched through a second store, and `fork()` before consumption can double-dispatch it. Shared-store thread tests do not establish cross-store, cross-process, or restart safety.
- The clock is sampled while the store lock is held, and that lock is not reentrant. A clock that re-enters the same store deadlocks.
- `ReplayStore` and `AuditLog` never evict, and denied `authorize` traffic grows the audit log. Neither store has a bound.
- HMAC key holders can forge records; the public demo key provides no adversarial authenticity.
- `verify_records` without an `expected_head` (`verify_prefix`) establishes integrity of the presented prefix only. Completeness requires a trusted expected head.
- Callback return does not establish an external business effect or production readiness.

Each named hazard is stated in full, with what fails and what still holds, in [the threat model](threat-model.md).

Commands and reporting requirements are in [reproducibility](reproducibility.md).
