from pathlib import Path

test = Path("crates/production-execution-authority-runtime/tests/persistent_chain.rs")
text = test.read_text()
old = '''    let mut receipts = Vec::with_capacity(graphic.compiled_plan.steps.len());
    for (index, step) in graphic.compiled_plan.steps.iter().enumerate() {
        let harness = live::harness(false)?;
        let permission = graphic_permission_for_step(&graphic, &step.operator_id)?;
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("graphic production step is missing Capability token ID")?
            .clone();
        let draft = CapabilityTokenDraft {
            token_id: token_id.clone(),
            subject: CapabilitySubject {
                executor_id: EXECUTOR_ID.to_owned(),
                device_id: Some(DEVICE_ID.to_owned()),
            },
            issued_at_epoch_s: live::LIVE_NOW,
            not_before_epoch_s: live::LIVE_NOW,
            expires_at_epoch_s: chain.approval.expires_at_epoch_s,
            max_uses: 1,
            nonce: format!("graphic-production-capability-nonce-{index:02}"),
            bindings: CapabilityBindings {
                contract_digest: graphic.compiled_contract.seal.contract_digest.clone(),
                capsule_digest: graphic.compiled_contract.seal.capsule_digest.clone(),
                plan_id: graphic.compiled_plan.plan_id.clone(),
                plan_digest: graphic.compiled_plan.plan_digest.clone(),
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            },
            grant: CapabilityGrant {
                capability: permission.capability.clone(),
                resource: permission.resource.clone(),
                access: permission.access,
                constraints: permission.constraints.clone(),
            },
        };
        authority.issue_capability(
            harness.transport,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            draft,
            live::LIVE_NOW,
            60,
        )?;
        let receipt = authority.consume_capability(
            &token_id,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            live::LIVE_NOW,
        )?;
        assert_eq!(receipt.use_number, 1);
        assert_eq!(receipt.max_uses, 1);
        receipts.push(receipt);
    }
    assert_eq!(receipts.len(), 4);
    assert_eq!(authority.chain_state().capabilities.len(), 4);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesConsumed
    );
'''
new = '''    let mut token_ids = Vec::with_capacity(graphic.compiled_plan.steps.len());
    for (index, step) in graphic.compiled_plan.steps.iter().enumerate() {
        let harness = live::harness(false)?;
        let permission = graphic_permission_for_step(&graphic, &step.operator_id)?;
        let token_id = step
            .capability_token_ids
            .first()
            .ok_or("graphic production step is missing Capability token ID")?
            .clone();
        let draft = CapabilityTokenDraft {
            token_id: token_id.clone(),
            subject: CapabilitySubject {
                executor_id: EXECUTOR_ID.to_owned(),
                device_id: Some(DEVICE_ID.to_owned()),
            },
            issued_at_epoch_s: live::LIVE_NOW,
            not_before_epoch_s: live::LIVE_NOW,
            expires_at_epoch_s: chain.approval.expires_at_epoch_s,
            max_uses: 1,
            nonce: format!("graphic-production-capability-nonce-{index:02}"),
            bindings: CapabilityBindings {
                contract_digest: graphic.compiled_contract.seal.contract_digest.clone(),
                capsule_digest: graphic.compiled_contract.seal.capsule_digest.clone(),
                plan_id: graphic.compiled_plan.plan_id.clone(),
                plan_digest: graphic.compiled_plan.plan_digest.clone(),
                step_id: step.step_id.clone(),
                operator_id: step.operator_id.clone(),
            },
            grant: CapabilityGrant {
                capability: permission.capability.clone(),
                resource: permission.resource.clone(),
                access: permission.access,
                constraints: permission.constraints.clone(),
            },
        };
        authority.issue_capability(
            harness.transport,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &chain.approved,
            &chain.approval,
            &chain.approve_receipt,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            draft,
            live::LIVE_NOW,
            60,
        )?;
        token_ids.push(token_id);
    }
    assert_eq!(authority.chain_state().capabilities.len(), 4);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesIssued
    );

    let mut receipts = Vec::with_capacity(token_ids.len());
    for token_id in &token_ids {
        let harness = live::harness(false)?;
        let receipt = authority.consume_capability(
            token_id,
            &harness.lease,
            &harness.accepted,
            &harness.deployment_policy,
            &graphic.compiled_contract,
            &graphic.compiled_plan,
            live::LIVE_NOW,
        )?;
        assert_eq!(receipt.use_number, 1);
        assert_eq!(receipt.max_uses, 1);
        receipts.push(receipt);
    }
    assert_eq!(receipts.len(), 4);
    assert_eq!(
        authority.chain_state().stage,
        ProductionExecutionStage::CapabilitiesConsumed
    );
'''
if new not in text:
    if old not in text:
        raise SystemExit("E3 issue/consume ordering anchor missing")
    test.write_text(text.replace(old, new, 1))
