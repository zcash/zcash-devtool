use std::collections::BTreeMap;
use std::fmt::Debug;

use zcash_client_backend::{
    encoding::AddressCodec,
    fees::TransactionBalance,
    proposal::{Proposal, ShieldedInputs, Step, StepOutput, StepOutputIndex},
    wallet::{Note, ReceivedNote, WalletTransparentOutput},
};
use zcash_protocol::{
    PoolType,
    consensus::Parameters,
    memo::{Memo, MemoBytes},
};
use zip321::TransactionRequest;

use crate::ui::format_zec;

/// Renders a [`Proposal`] to stdout in a structured, human-readable form.
pub(crate) fn print_proposal<P: Parameters, FeeRuleT: Debug, NoteRef>(
    label: &str,
    proposal: &Proposal<FeeRuleT, NoteRef>,
    params: &P,
) {
    println!("{label}:");
    println!(
        "  Min target height: {}",
        u32::from(proposal.min_target_height()),
    );
    println!("  Fee rule: {:?}", proposal.fee_rule());
    let steps = proposal.steps();
    println!("  Steps ({}):", steps.len());
    for (i, step) in steps.iter().enumerate() {
        print_step(i, step, params);
    }
}

fn print_step<P: Parameters, NoteRef>(index: usize, step: &Step<NoteRef>, params: &P) {
    println!("    Step {index}:");
    println!("      Shielding: {}", step.is_shielding());
    print_payments(step.transaction_request(), step.payment_pools());
    print_transparent_inputs(step.transparent_inputs(), params);
    print_shielded_inputs(step.shielded_inputs());
    print_prior_step_inputs(step.prior_step_inputs());
    print_balance(step.balance());
}

fn print_payments(request: &TransactionRequest, payment_pools: &BTreeMap<usize, PoolType>) {
    let payments = request.payments();
    println!("      Payments ({}):", payments.len());
    for (idx, payment) in payments {
        let pool = payment_pools
            .get(idx)
            .map(|p| p.to_string())
            .unwrap_or_else(|| "?".to_owned());
        println!("        [{idx}] -> {}", payment.recipient_address());
        println!(
            "            Amount: {}",
            payment
                .amount()
                .map(format_zec)
                .unwrap_or_else(|| "<unspecified>".to_owned()),
        );
        println!("            Pool: {pool}");
        if let Some(memo) = payment.memo() {
            print_memo(12, memo);
        }
        if let Some(label) = payment.label() {
            println!("            Label: {label}");
        }
        if let Some(message) = payment.message() {
            println!("            Message: {message}");
        }
        for (k, v) in payment.other_params() {
            println!("            {k}: {v}");
        }
    }
}

fn print_transparent_inputs<P: Parameters>(inputs: &[WalletTransparentOutput], params: &P) {
    if inputs.is_empty() {
        return;
    }
    println!("      Transparent inputs ({}):", inputs.len());
    for input in inputs {
        let outpoint = input.outpoint();
        println!(
            "        - {}:{}  {}  -> {}",
            outpoint.txid(),
            outpoint.n(),
            format_zec(input.value()),
            input.recipient_address().encode(params),
        );
    }
}

fn print_shielded_inputs<NoteRef>(inputs: Option<&ShieldedInputs<NoteRef>>) {
    let Some(inputs) = inputs else {
        return;
    };
    let notes = inputs.notes();
    println!(
        "      Shielded inputs ({}) at anchor height {}:",
        notes.len(),
        u32::from(inputs.anchor_height()),
    );
    for received in notes.iter() {
        print_received_note(received);
    }
}

fn print_received_note<NoteRef>(received: &ReceivedNote<NoteRef, Note>) {
    let pool = match received.note() {
        Note::Sapling(_) => "Sapling",
        Note::Orchard(_) => "Orchard",
    };
    println!(
        "        - {pool} {}:{}  {}",
        received.txid(),
        received.output_index(),
        format_zec(received.note().value()),
    );
}

fn print_prior_step_inputs(refs: &[StepOutput]) {
    if refs.is_empty() {
        return;
    }
    println!("      Prior step inputs ({}):", refs.len());
    for r in refs {
        let kind = match r.output_index() {
            StepOutputIndex::Payment(j) => format!("Payment {j}"),
            StepOutputIndex::Change(j) => format!("Change {j}"),
        };
        println!("        - Step {} {kind}", r.step_index());
    }
}

fn print_balance(balance: &TransactionBalance) {
    let changes = balance.proposed_change();
    println!("      Change outputs ({}):", changes.len());
    for change in changes {
        let mut line = format!(
            "        - {} {}",
            change.output_pool(),
            format_zec(change.value()),
        );
        if change.is_ephemeral() {
            line.push_str(" [ephemeral]");
        }
        println!("{line}");
        if let Some(memo) = change.memo() {
            print_memo(12, memo);
        }
    }
    println!("      Fee: {}", format_zec(balance.fee_required()));
}

fn print_memo(indent: usize, memo: &MemoBytes) {
    let pad = " ".repeat(indent);
    match Memo::try_from(memo) {
        Ok(Memo::Empty) => {}
        Ok(Memo::Text(text)) => println!("{pad}Memo (text): {}", &*text),
        Ok(Memo::Arbitrary(bytes)) => {
            println!("{pad}Memo (arbitrary): {}", hex::encode(&bytes[..]))
        }
        Ok(Memo::Future(bytes)) => {
            println!("{pad}Memo (future): {}", hex::encode(bytes.as_slice()))
        }
        Err(_) => println!("{pad}Memo (raw): {}", hex::encode(memo.as_slice())),
    }
}
