use clearing_solana_program::{instruction::InitializeArgs, pda, state::Config, ID as PROGRAM_ID};
use mollusk_svm::{program::keyed_account_for_system_program, result::Check, Mollusk};
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

fn setup_mollusk() -> Mollusk {
    std::env::set_var("SBF_OUT_DIR", env!("SBF_OUT_DIR"));
    Mollusk::new(&PROGRAM_ID, "clearing_solana_program")
}

#[test]
fn initialize_writes_genesis_root_and_keys() {
    let mollusk = setup_mollusk();

    let payer = Pubkey::new_from_array([7u8; 32]);
    let (config, _bump) = pda::find_config(&PROGRAM_ID);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (system_program, system_account) = keyed_account_for_system_program();

    let genesis_root = [0x11u8; 32];
    let admin = [0x22u8; 32];
    let matcher_key = [0x33u8; 32];
    let freeze_authority = [0x44u8; 32];
    let guest_vk_hash = [0x55u8; 32];
    let groth16_vk_hash_prefix = [0x66, 0x77, 0x88, 0x99];

    let args = InitializeArgs {
        genesis_root,
        admin,
        matcher_key,
        freeze_authority,
        guest_vk_hash,
        groth16_vk_hash_prefix,
        proof_version: 0,
    };

    let instruction = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new_readonly(system_program, false),
        ],
        data: args.pack().to_vec(),
    };

    let accounts = [
        (payer, Account::new(1_000_000_000, 0, &system_program)),
        (config, Account::default()),
        (vk_account, Account::default()),
        (system_program, system_account),
    ];

    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);

    let config_account = result
        .resulting_accounts
        .iter()
        .find(|(key, _)| key == &config)
        .expect("config account missing")
        .1
        .clone();

    let cfg = Config::unpack(&config_account.data).expect("config unpack");
    assert_eq!(cfg.root, genesis_root);
    assert_eq!(cfg.admin, admin);
    assert_eq!(cfg.matcher_key, matcher_key);
    assert_eq!(cfg.freeze_authority, freeze_authority);
    assert_eq!(cfg.guest_vk_hash, guest_vk_hash);
    assert_eq!(cfg.groth16_vk_hash_prefix, groth16_vk_hash_prefix);
    assert_eq!(cfg.vk_account, *vk_account.as_array());
    assert_eq!(cfg.batch_seq, 0);
    assert_eq!(cfg.expiry_height, 0);
    assert_eq!(cfg.next_deposit_nonce, 0);
    assert_eq!(cfg.next_asset_id, 0);
    assert_eq!(cfg.frozen, 0);
    assert_eq!(cfg.proof_version, 0);
    assert_ne!(cfg.admin, cfg.matcher_key);
}
