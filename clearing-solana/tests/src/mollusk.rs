use clearing_solana_program::{
    error::ClearingError, instruction::InitializeArgs, pda, state::Config, ID as PROGRAM_ID,
};
use mollusk_svm::{program::keyed_account_for_system_program, result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

fn setup_mollusk() -> Mollusk {
    std::env::set_var("SBF_OUT_DIR", env!("SBF_OUT_DIR"));
    Mollusk::new(&PROGRAM_ID, "clearing_solana_program")
}

fn init_args() -> InitializeArgs {
    InitializeArgs {
        genesis_root: [0x11u8; 32],
        admin: [0x22u8; 32],
        matcher_key: [0x33u8; 32],
        freeze_authority: [0x44u8; 32],
        guest_vk_hash: [0x55u8; 32],
        groth16_vk_hash_prefix: [0x66, 0x77, 0x88, 0x99],
        proof_version: 0,
    }
}

fn initialize_ix(payer: Pubkey, config: Pubkey, vk_account: Pubkey, system: Pubkey) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new_readonly(system, false),
        ],
        data: init_args().pack().to_vec(),
    }
}

#[test]
fn initialize_writes_genesis_root_and_keys() {
    let mollusk = setup_mollusk();

    let payer = Pubkey::new_from_array([7u8; 32]);
    let (config, config_bump) = pda::find_config(&PROGRAM_ID);
    let (_vault_authority, vault_authority_bump) = pda::find_vault_authority(&PROGRAM_ID);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (system_program, system_account) = keyed_account_for_system_program();
    let args = init_args();

    let instruction = initialize_ix(payer, config, vk_account, system_program);
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (config, Account::default()),
        (vk_account, Account::default()),
        (system_program, system_account),
    ];

    let result = mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[
            Check::success(),
            Check::account(&config)
                .owner(&PROGRAM_ID)
                .space(Config::LEN)
                .build(),
        ],
    );

    let config_account = &result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config)
        .expect("config account missing")
        .1;

    let cfg = Config::unpack(&config_account.data).expect("config unpack");
    assert_eq!(cfg.bump, config_bump);
    assert_eq!(cfg.vault_authority_bump, vault_authority_bump);
    assert_eq!(config_account.data.len(), Config::LEN);
    assert_eq!(cfg.root, args.genesis_root);
    assert_eq!(cfg.admin, args.admin);
    assert_eq!(cfg.matcher_key, args.matcher_key);
    assert_eq!(cfg.freeze_authority, args.freeze_authority);
    assert_eq!(cfg.guest_vk_hash, args.guest_vk_hash);
    assert_eq!(cfg.groth16_vk_hash_prefix, args.groth16_vk_hash_prefix);
    assert_eq!(cfg.vk_account, *vk_account.as_array());
    assert_eq!(cfg.batch_seq, 0);
    assert_eq!(cfg.expiry_height, 0);
    assert_eq!(cfg.next_deposit_nonce, 0);
    assert_eq!(cfg.next_asset_id, 0);
    assert_eq!(cfg.frozen, 0);
    assert_eq!(cfg.proof_version, 0);
    assert_ne!(cfg.admin, cfg.matcher_key);
}

#[test]
fn initialize_rejects_already_initialized() {
    let mollusk = setup_mollusk();

    let payer = Pubkey::new_from_array([7u8; 32]);
    let (config, _bump) = pda::find_config(&PROGRAM_ID);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (system_program, system_account) = keyed_account_for_system_program();

    let instruction = initialize_ix(payer, config, vk_account, system_program);
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (config, Account::default()),
        (vk_account, Account::default()),
        (system_program, system_account),
    ];

    let first =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    mollusk.process_and_validate_instruction(
        &instruction,
        &first.resulting_accounts,
        &[Check::err(ProgramError::Custom(
            ClearingError::AlreadyInitialized as u32,
        ))],
    );
}

#[test]
fn initialize_rejects_wrong_config_pda() {
    let mollusk = setup_mollusk();

    let payer = Pubkey::new_from_array([7u8; 32]);
    let not_config = Pubkey::new_from_array([3u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (system_program, system_account) = keyed_account_for_system_program();

    let instruction = initialize_ix(payer, not_config, vk_account, system_program);
    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (not_config, Account::default()),
        (vk_account, Account::default()),
        (system_program, system_account),
    ];

    mollusk.process_and_validate_instruction(
        &instruction,
        &accounts,
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidPda as u32,
        ))],
    );
}
