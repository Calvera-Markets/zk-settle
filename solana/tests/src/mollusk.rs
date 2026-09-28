use clearing_solana_program::{
    error::ClearingError,
    instruction::{
        pack_public_values, InitializeArgs, RotateVkArgs, SetAdminArgs, SettleArgs,
        SETTLE_PROOF_LEN,
    },
    pda,
    state::{BatchRecord, Config},
    ID as PROGRAM_ID,
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

const ADMIN: Pubkey = Pubkey::new_from_array([0x22u8; 32]);
const MATCHER_KEY: [u8; 32] = [0x33u8; 32];
const GENESIS_ROOT: [u8; 32] = [0x11u8; 32];
const NEW_ROOT_1: [u8; 32] = [0xAAu8; 32];
const NEW_ROOT_2: [u8; 32] = [0xBBu8; 32];
const WITHDRAWALS_ROOT: [u8; 32] = [0xCCu8; 32];
const DA_HASH: [u8; 32] = [0xDDu8; 32];

fn funded_system_account(system_program: &Pubkey) -> Account {
    Account::new(1_000_000_000, 0, system_program)
}

fn initialize_for_settle(
    mollusk: &Mollusk,
    payer: Pubkey,
    vk_account: Pubkey,
) -> (Pubkey, Account, Account, Pubkey, Account) {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (system_program, system_account) = keyed_account_for_system_program();
    let instruction = initialize_ix(payer, config, vk_account, system_program);
    let accounts = [
        (payer, funded_system_account(&system_program)),
        (config, Account::default()),
        (vk_account, Account::default()),
        (system_program, system_account.clone()),
    ];
    let result =
        mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
    let config_acc = result.get_account(&config).expect("config").clone();
    (
        config,
        config_acc,
        result.get_account(&vk_account).expect("vk").clone(),
        system_program,
        system_account,
    )
}

fn settle_args(
    prev_root: [u8; 32],
    new_root: [u8; 32],
    matcher_key: [u8; 32],
    batch_seq: u64,
    expiry_height: u64,
) -> SettleArgs {
    SettleArgs {
        proof: [0u8; SETTLE_PROOF_LEN],
        public_values: pack_public_values(
            &prev_root,
            &new_root,
            &WITHDRAWALS_ROOT,
            &matcher_key,
            batch_seq,
            expiry_height,
        ),
        da_hash: DA_HASH,
    }
}

fn settle_ix(
    admin: Pubkey,
    config: Pubkey,
    vk_account: Pubkey,
    batch: Pubkey,
    system: Pubkey,
    args: &SettleArgs,
) -> Instruction {
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new(batch, false),
            AccountMeta::new_readonly(system, false),
        ],
        data: args.pack().to_vec(),
    }
}

fn batch_pda(seq: u64) -> (Pubkey, u8) {
    pda::find_batch(&PROGRAM_ID, &seq.to_le_bytes())
}

#[test]
fn settle_advances_root_and_writes_batch_record() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let (batch, batch_bump) = batch_pda(0);
    let args = settle_args(GENESIS_ROOT, NEW_ROOT_1, MATCHER_KEY, 0, 0);

    let result = mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch, system_program, &args),
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc),
            (batch, Account::default()),
            (system_program, system_account),
        ],
        &[
            Check::success(),
            Check::account(&batch)
                .owner(&PROGRAM_ID)
                .space(BatchRecord::LEN)
                .build(),
        ],
    );

    let cfg = Config::unpack(&result.get_account(&config).expect("config").data).unwrap();
    assert_eq!(cfg.root, NEW_ROOT_1);
    assert_eq!(cfg.batch_seq, 1);
    assert_eq!(cfg.expiry_height, 0);
    assert_ne!(cfg.admin, cfg.matcher_key);

    let rec = BatchRecord::unpack(&result.get_account(&batch).expect("batch").data).unwrap();
    assert_eq!(rec.bump, batch_bump);
    assert_eq!(rec.seq, 0);
    assert_eq!(rec.new_root, NEW_ROOT_1);
    assert_eq!(rec.withdrawals_root, WITHDRAWALS_ROOT);
    assert_eq!(rec.da_hash, DA_HASH);
}

#[test]
fn settle_rejects_wrong_prev_root() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let (batch, _) = batch_pda(0);
    let args = settle_args([0xFFu8; 32], NEW_ROOT_1, MATCHER_KEY, 0, 0);

    mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch, system_program, &args),
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc),
            (batch, Account::default()),
            (system_program, system_account),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );
}

#[test]
fn settle_rejects_wrong_matcher_key() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let (batch, _) = batch_pda(0);
    let args = settle_args(GENESIS_ROOT, NEW_ROOT_1, [0xEEu8; 32], 0, 0);

    mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch, system_program, &args),
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc),
            (batch, Account::default()),
            (system_program, system_account),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );
}

#[test]
fn settle_rejects_wrong_admin_signer() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let impostor = Pubkey::new_from_array([0x99u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let (batch, _) = batch_pda(0);
    let args = settle_args(GENESIS_ROOT, NEW_ROOT_1, MATCHER_KEY, 0, 0);

    mollusk.process_and_validate_instruction(
        &settle_ix(impostor, config, vk_account, batch, system_program, &args),
        &[
            (impostor, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc),
            (batch, Account::default()),
            (system_program, system_account),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::Unauthorized as u32,
        ))],
    );
}

#[test]
fn settle_rejects_frozen() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, mut config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let mut cfg = Config::unpack(&config_acc.data).unwrap();
    cfg.frozen = 1;
    cfg.pack(&mut config_acc.data).unwrap();

    let (batch, _) = batch_pda(0);
    let args = settle_args(GENESIS_ROOT, NEW_ROOT_1, MATCHER_KEY, 0, 0);

    mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch, system_program, &args),
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc),
            (batch, Account::default()),
            (system_program, system_account),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::Frozen as u32,
        ))],
    );
}

#[test]
fn second_settle_requires_previous_new_root() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let (batch0, _) = batch_pda(0);
    let args0 = settle_args(GENESIS_ROOT, NEW_ROOT_1, MATCHER_KEY, 0, 0);

    let first = mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch0, system_program, &args0),
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc),
            (vk_account, vk_acc.clone()),
            (batch0, Account::default()),
            (system_program, system_account.clone()),
        ],
        &[Check::success()],
    );

    let cfg_after = Config::unpack(&first.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg_after.root, NEW_ROOT_1);
    assert_eq!(cfg_after.batch_seq, 1);

    let (batch1, _) = batch_pda(1);
    let stale = settle_args(GENESIS_ROOT, NEW_ROOT_2, MATCHER_KEY, 1, 0);
    mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch1, system_program, &stale),
        &[
            (ADMIN, first.get_account(&ADMIN).expect("admin").clone()),
            (config, first.get_account(&config).unwrap().clone()),
            (vk_account, vk_acc.clone()),
            (batch1, Account::default()),
            (system_program, system_account.clone()),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::InvalidProof as u32,
        ))],
    );

    let args1 = settle_args(NEW_ROOT_1, NEW_ROOT_2, MATCHER_KEY, 1, 0);
    let second = mollusk.process_and_validate_instruction(
        &settle_ix(ADMIN, config, vk_account, batch1, system_program, &args1),
        &[
            (ADMIN, first.get_account(&ADMIN).expect("admin").clone()),
            (config, first.get_account(&config).unwrap().clone()),
            (vk_account, vk_acc),
            (batch1, Account::default()),
            (system_program, system_account),
        ],
        &[Check::success()],
    );

    let cfg = Config::unpack(&second.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.root, NEW_ROOT_2);
    assert_eq!(cfg.batch_seq, 2);
    assert_eq!(cfg.expiry_height, 0);

    let rec1 = BatchRecord::unpack(&second.get_account(&batch1).unwrap().data).unwrap();
    assert_eq!(rec1.seq, 1);
    assert_eq!(rec1.new_root, NEW_ROOT_2);
}

#[test]
fn set_admin_and_rotate_vk() {
    let mollusk = setup_mollusk();
    let payer = Pubkey::new_from_array([7u8; 32]);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let (config, config_acc, vk_acc, system_program, system_account) =
        initialize_for_settle(&mollusk, payer, vk_account);
    let new_admin = Pubkey::new_from_array([0xABu8; 32]);
    let set = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(ADMIN, true),
            AccountMeta::new(config, false),
        ],
        data: SetAdminArgs {
            new_admin: *new_admin.as_array(),
        }
        .pack()
        .to_vec(),
    };
    let after_set = mollusk.process_and_validate_instruction(
        &set,
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, config_acc.clone()),
        ],
        &[Check::success()],
    );
    let cfg = Config::unpack(&after_set.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.admin, *new_admin.as_array());
    assert_eq!(cfg.matcher_key, MATCHER_KEY);

    let impostor = mollusk.process_and_validate_instruction(
        &set,
        &[
            (ADMIN, funded_system_account(&system_program)),
            (config, after_set.get_account(&config).unwrap().clone()),
        ],
        &[Check::err(ProgramError::Custom(
            ClearingError::Unauthorized as u32,
        ))],
    );
    let _ = impostor;

    let new_vk = Pubkey::new_from_array([0xEEu8; 32]);
    let rotate = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(new_admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(new_vk, false),
        ],
        data: RotateVkArgs {
            guest_vk_hash: [0x11u8; 32],
            groth16_vk_hash_prefix: [1, 2, 3, 4],
            proof_version: 1,
        }
        .pack()
        .to_vec(),
    };
    let after_rot = mollusk.process_and_validate_instruction(
        &rotate,
        &[
            (new_admin, funded_system_account(&system_program)),
            (config, after_set.get_account(&config).unwrap().clone()),
            (new_vk, Account::default()),
            (vk_account, vk_acc),
            (system_program, system_account),
        ],
        &[Check::success()],
    );
    let cfg = Config::unpack(&after_rot.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.vk_account, *new_vk.as_array());
    assert_eq!(cfg.guest_vk_hash, [0x11u8; 32]);
    assert_eq!(cfg.proof_version, 1);
}
