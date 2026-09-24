use clearing::account::Account;
use clearing::commitment::hash_plain::Sha256Hasher;
use clearing::commitment::{canonical_encode, StateTree};
use clearing::commitment::{withdrawal_proof, withdrawals_root};
use clearing::id::{AccountId, Amount, AssetId, L1Address};
use ark_bn254::{Bn254, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use clearing_circuits::tree::MerkleTree;
use clearing_circuits::{
    solana as circuits_solana, ClaimOpenCircuit, CommitRootsCircuit, DEPTH as CIRCUITS_DEPTH,
};
use clearing_solana_program::{
    error::ClearingError,
    instruction::{
        self, pack_public_values, pack_rotate_open_vk, ClaimArgs, DepositArgs, EscapeWithdrawArgs,
        InitializeArgs, RegisterMintArgs, RotateVkArgs, SetAdminArgs, SettleArgs,
        PROOF_VERSION_CIRCUITS, SETTLE_PROOF_LEN,
    },
    pda,
    state::{AccountOwner, BatchRecord, Config, DepositReceipt, MintMeta, Nullifier},
    token::MAX_REGISTERED_MINTS,
    verifier::{encode_vk_account, PROOF_LEN},
    ID as PROGRAM_ID,
};
use litesvm::LiteSVM;
use solana_account::Account as SolAccount;
use solana_instruction::error::InstructionError;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_program_pack::Pack;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_transaction_error::TransactionError;
use spl_token_2022_interface::{
    extension::ExtensionType,
    instruction as token_2022_ix,
    state::{Account as TokenAccount, Mint},
    ID as TOKEN_2022,
};
use spl_token_interface::ID as TOKENKEG;
use uuid::Uuid;

const DECIMALS: u8 = 6;
/// Design-doc squat example: first signer binds this id forever.
const ACCOUNT_ID: [u8; 16] = [0x0B; 16];

fn program_elf() -> Vec<u8> {
    std::fs::read(format!(
        "{}/clearing_solana_program.so",
        env!("SBF_OUT_DIR")
    ))
    .expect("sbf program")
}

fn setup_svm() -> LiteSVM {
    let mut svm = LiteSVM::new();
    svm.add_program(PROGRAM_ID, &program_elf()).unwrap();
    svm
}

fn airdrop(svm: &mut LiteSVM, pk: &Pubkey) {
    svm.airdrop(pk, 10_000_000_000).unwrap();
}

fn send(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ixs: &[Instruction]) {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).unwrap();
}

fn send_ok(svm: &mut LiteSVM, payer: &Keypair, signers: &[&Keypair], ixs: &[Instruction]) -> u64 {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        signers,
        svm.latest_blockhash(),
    );
    svm.send_transaction(tx).unwrap().compute_units_consumed
}

fn send_custom_err(
    svm: &mut LiteSVM,
    payer: &Keypair,
    signers: &[&Keypair],
    ixs: &[Instruction],
) -> u32 {
    let tx = Transaction::new_signed_with_payer(
        ixs,
        Some(&payer.pubkey()),
        signers,
        svm.latest_blockhash(),
    );
    match svm.send_transaction(tx).unwrap_err().err {
        TransactionError::InstructionError(_, InstructionError::Custom(code)) => code,
        other => panic!("unexpected error: {other:?}"),
    }
}

fn init_args(admin: Pubkey) -> InitializeArgs {
    InitializeArgs {
        genesis_root: [0x11u8; 32],
        admin: *admin.as_array(),
        matcher_key: [0x33u8; 32],
        freeze_authority: [0x44u8; 32],
        guest_vk_hash: [0x55u8; 32],
        groth16_vk_hash_prefix: [0x66, 0x77, 0x88, 0x99],
        proof_version: 0,
    }
}

fn initialize(svm: &mut LiteSVM, payer: &Keypair, admin: Pubkey) -> Pubkey {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: init_args(admin).pack().to_vec(),
    };
    send(svm, payer, &[payer], &[ix]);
    config
}

fn create_mint(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint_authority: &Pubkey,
    token_program: &Pubkey,
    space: usize,
) -> Keypair {
    let mint = Keypair::new();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let create = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        token_program,
    );
    let init = if *token_program == TOKEN_2022 {
        token_2022_ix::initialize_mint2(
            token_program,
            &mint.pubkey(),
            mint_authority,
            None,
            DECIMALS,
        )
        .unwrap()
    } else {
        spl_token_interface::instruction::initialize_mint2(
            token_program,
            &mint.pubkey(),
            mint_authority,
            None,
            DECIMALS,
        )
        .unwrap()
    };
    send(svm, payer, &[payer, &mint], &[create, init]);
    mint
}

fn create_token_2022_mint(svm: &mut LiteSVM, payer: &Keypair, mint_authority: &Pubkey) -> Keypair {
    create_mint(svm, payer, mint_authority, &TOKEN_2022, Mint::LEN)
}

fn create_token_account(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    owner: &Pubkey,
) -> Keypair {
    let ata = Keypair::new();
    let space = TokenAccount::LEN;
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let create = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &ata.pubkey(),
        rent,
        space as u64,
        &TOKEN_2022,
    );
    let init = token_2022_ix::initialize_account3(&TOKEN_2022, &ata.pubkey(), mint, owner).unwrap();
    send(svm, payer, &[payer, &ata], &[create, init]);
    ata
}

fn mint_to(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint_authority: &Keypair,
    mint: &Pubkey,
    dest: &Pubkey,
    amount: u64,
) {
    let ix = token_2022_ix::mint_to(
        &TOKEN_2022,
        mint,
        dest,
        &mint_authority.pubkey(),
        &[],
        amount,
    )
    .unwrap();
    send(svm, payer, &[payer, mint_authority], &[ix]);
}

fn register_mint_ix(admin: Pubkey, mint: Pubkey, decimals: u8) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (mint_meta, _) = pda::find_mint_meta(&PROGRAM_ID, mint.as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.as_array());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new(mint_meta, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: RegisterMintArgs { decimals }.pack().to_vec(),
    }
}

fn deposit_ix(
    owner: Pubkey,
    owner_ata: Pubkey,
    mint: Pubkey,
    nonce: u64,
    args: DepositArgs,
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (mint_meta, _) = pda::find_mint_meta(&PROGRAM_ID, mint.as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.as_array());
    let (account_owner, _) = pda::find_account_owner(&PROGRAM_ID, &args.account_id);
    let (receipt, _) = pda::find_deposit_receipt(&PROGRAM_ID, &nonce.to_le_bytes());
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(owner_ata, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(mint_meta, false),
            AccountMeta::new(config, false),
            AccountMeta::new(account_owner, false),
            AccountMeta::new(receipt, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: args.pack().as_slice().to_vec(),
    }
}

fn token_amount(svm: &LiteSVM, account: &Pubkey) -> u64 {
    let acc = svm.get_account(account).expect("token account");
    TokenAccount::unpack(&acc.data)
        .expect("unpack token")
        .amount
}

fn poke_config(svm: &mut LiteSVM, config: &Pubkey, f: impl FnOnce(&mut Config)) {
    let mut acc = svm.get_account(config).expect("config");
    let mut cfg = Config::unpack(&acc.data).expect("unpack config");
    f(&mut cfg);
    cfg.pack(&mut acc.data).expect("pack config");
    svm.set_account(*config, acc).expect("set config");
}

#[test]
fn register_mint_happy_path() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());

    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );

    let (mint_meta, meta_bump) = pda::find_mint_meta(&PROGRAM_ID, mint.pubkey().as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.pubkey().as_array());
    let (vault_authority, _) = pda::find_vault_authority(&PROGRAM_ID);

    let meta_acc = svm.get_account(&mint_meta).expect("mint_meta");
    assert_eq!(meta_acc.owner, PROGRAM_ID);
    let meta = MintMeta::unpack(&meta_acc.data).expect("unpack mint_meta");
    assert_eq!(meta.bump, meta_bump);
    assert_eq!(meta.decimals, DECIMALS);
    assert_eq!(meta.asset_id, 0);
    assert_eq!(meta.mint, *mint.pubkey().as_array());
    assert_eq!(meta.vault, *vault.as_array());

    let vault_acc = svm.get_account(&vault).expect("vault");
    assert_eq!(vault_acc.owner, TOKEN_2022);
    let vault_token = TokenAccount::unpack(&vault_acc.data).expect("unpack vault");
    assert_eq!(vault_token.mint, mint.pubkey());
    assert_eq!(vault_token.owner, vault_authority);
    assert_eq!(vault_token.amount, 0);

    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.next_asset_id, 1);
    assert_ne!(cfg.admin, cfg.matcher_key);
}

#[test]
fn register_mint_rejects_tokenkeg() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_mint(
        &mut svm,
        &payer,
        &payer.pubkey(),
        &TOKENKEG,
        spl_token_interface::state::Mint::LEN,
    );

    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    assert_eq!(err, ClearingError::UnsupportedMint as u32);
}

#[test]
fn register_mint_rejects_extension() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());

    let mint = Keypair::new();
    let space =
        ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::MintCloseAuthority])
            .unwrap();
    let rent = svm.minimum_balance_for_rent_exemption(space);
    let create = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &TOKEN_2022,
    );
    let close_auth = token_2022_ix::initialize_mint_close_authority(
        &TOKEN_2022,
        &mint.pubkey(),
        Some(&payer.pubkey()),
    )
    .unwrap();
    let init = token_2022_ix::initialize_mint2(
        &TOKEN_2022,
        &mint.pubkey(),
        &payer.pubkey(),
        None,
        DECIMALS,
    )
    .unwrap();
    send(
        &mut svm,
        &payer,
        &[&payer, &mint],
        &[create, close_auth, init],
    );

    let mint_acc = svm.get_account(&mint.pubkey()).unwrap();
    assert!(mint_acc.data.len() > Mint::LEN);

    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    assert_eq!(err, ClearingError::UnsupportedMint as u32);
}

fn funded_user(
    svm: &mut LiteSVM,
    payer: &Keypair,
    mint: &Pubkey,
    amount: u64,
) -> (Keypair, Keypair) {
    let user = Keypair::new();
    airdrop(svm, &user.pubkey());
    let ata = create_token_account(svm, payer, mint, &user.pubkey());
    if amount > 0 {
        mint_to(svm, payer, payer, mint, &ata.pubkey(), amount);
    }
    (user, ata)
}

#[test]
fn deposit_transfers_and_binds_owner() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );

    let amount = 1_000u64;
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), amount);
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.pubkey().as_array());
    assert_eq!(token_amount(&svm, &ata.pubkey()), amount);
    assert_eq!(token_amount(&svm, &vault), 0);

    let args = DepositArgs {
        account_id: ACCOUNT_ID,
        amount,
        trading_key: None,
    };
    send(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            args,
        )],
    );

    assert_eq!(token_amount(&svm, &ata.pubkey()), 0);
    assert_eq!(token_amount(&svm, &vault), amount);

    let (acct_pda, acct_bump) = pda::find_account_owner(&PROGRAM_ID, &ACCOUNT_ID);
    let acct = AccountOwner::unpack(&svm.get_account(&acct_pda).unwrap().data).unwrap();
    assert_eq!(acct.bump, acct_bump);
    assert_eq!(acct.owner, *user.pubkey().as_array());
    assert_eq!(acct.trading_key_set, 0);

    let (receipt_pda, receipt_bump) = pda::find_deposit_receipt(&PROGRAM_ID, &0u64.to_le_bytes());
    let rec = DepositReceipt::unpack(&svm.get_account(&receipt_pda).unwrap().data).unwrap();
    assert_eq!(rec.bump, receipt_bump);
    assert_eq!(rec.nonce, 0);
    assert_eq!(rec.account_id, ACCOUNT_ID);
    assert_eq!(rec.asset_id, 0);
    assert_eq!(rec.amount, amount);
    assert_eq!(rec.owner, *user.pubkey().as_array());
    assert_eq!(rec.trading_key, [0u8; 32]);

    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.next_deposit_nonce, 1);

    let other = Keypair::new();
    airdrop(&mut svm, &other.pubkey());
    let other_ata = create_token_account(&mut svm, &payer, &mint.pubkey(), &other.pubkey());
    mint_to(
        &mut svm,
        &payer,
        &payer,
        &mint.pubkey(),
        &other_ata.pubkey(),
        amount,
    );
    let err = send_custom_err(
        &mut svm,
        &other,
        &[&other],
        &[deposit_ix(
            other.pubkey(),
            other_ata.pubkey(),
            mint.pubkey(),
            1,
            args,
        )],
    );
    assert_eq!(err, ClearingError::OwnerMismatch as u32);
}

#[test]
fn later_deposit_rejects_trading_key_even_if_first_was_none() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );

    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 2_000);
    send(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 1_000,
                trading_key: None,
            },
        )],
    );

    let (acct_pda, _) = pda::find_account_owner(&PROGRAM_ID, &ACCOUNT_ID);
    let acct = AccountOwner::unpack(&svm.get_account(&acct_pda).unwrap().data).unwrap();
    assert_eq!(acct.trading_key_set, 0);

    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            1,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 1_000,
                trading_key: Some([0xABu8; 32]),
            },
        )],
    );
    assert_eq!(err, ClearingError::KeyAlreadyRegistered as u32);
}

#[test]
fn second_deposit_increments_nonce_and_new_receipt() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );

    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 2_000);
    let first = DepositArgs {
        account_id: ACCOUNT_ID,
        amount: 700,
        trading_key: Some([0xCDu8; 32]),
    };
    send(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            first,
        )],
    );

    let (acct_pda, _) = pda::find_account_owner(&PROGRAM_ID, &ACCOUNT_ID);
    let acct = AccountOwner::unpack(&svm.get_account(&acct_pda).unwrap().data).unwrap();
    assert_eq!(acct.trading_key_set, 1);

    let (r0, _) = pda::find_deposit_receipt(&PROGRAM_ID, &0u64.to_le_bytes());
    let rec0 = DepositReceipt::unpack(&svm.get_account(&r0).unwrap().data).unwrap();
    assert_eq!(rec0.nonce, 0);
    assert_eq!(rec0.trading_key, [0xCDu8; 32]);
    assert_eq!(rec0.amount, 700);

    send(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            1,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 300,
                trading_key: None,
            },
        )],
    );

    let (r1, _) = pda::find_deposit_receipt(&PROGRAM_ID, &1u64.to_le_bytes());
    assert_ne!(r0, r1);
    let rec1 = DepositReceipt::unpack(&svm.get_account(&r1).unwrap().data).unwrap();
    assert_eq!(rec1.nonce, 1);
    assert_eq!(rec1.amount, 300);
    assert_eq!(rec1.trading_key, [0u8; 32]);
    assert_eq!(rec1.account_id, ACCOUNT_ID);
    assert_eq!(rec1.owner, *user.pubkey().as_array());

    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.next_deposit_nonce, 2);

    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.pubkey().as_array());
    assert_eq!(token_amount(&svm, &vault), 1_000);
    assert_eq!(token_amount(&svm, &ata.pubkey()), 1_000);
}

#[test]
fn deposit_rejects_frozen() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 1_000);
    poke_config(&mut svm, &config, |cfg| cfg.frozen = 1);

    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 1_000,
                trading_key: None,
            },
        )],
    );
    assert_eq!(err, ClearingError::Frozen as u32);
}

#[test]
fn deposit_rejects_zero_amount() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 1_000);

    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 0,
                trading_key: None,
            },
        )],
    );
    assert_eq!(err, ClearingError::NonPositiveQuantity as u32);
}

#[test]
fn register_mint_rejects_seventeenth() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    poke_config(&mut svm, &config, |cfg| {
        cfg.next_asset_id = MAX_REGISTERED_MINTS;
    });
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());

    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    assert_eq!(err, ClearingError::Overflow as u32);
}

#[test]
fn register_mint_rejects_non_admin() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    let stranger = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    airdrop(&mut svm, &stranger.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());

    let err = send_custom_err(
        &mut svm,
        &stranger,
        &[&stranger],
        &[register_mint_ix(stranger.pubkey(), mint.pubkey(), DECIMALS)],
    );
    assert_eq!(err, ClearingError::Unauthorized as u32);
}

#[test]
fn register_mint_rejects_freeze_authority() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    initialize(&mut svm, &payer, admin.pubkey());
    let mint = Keypair::new();
    let rent = svm.minimum_balance_for_rent_exemption(Mint::LEN);
    let create = solana_system_interface::instruction::create_account(
        &payer.pubkey(),
        &mint.pubkey(),
        rent,
        Mint::LEN as u64,
        &TOKEN_2022,
    );
    let init = token_2022_ix::initialize_mint2(
        &TOKEN_2022,
        &mint.pubkey(),
        &payer.pubkey(),
        Some(&payer.pubkey()),
        DECIMALS,
    )
    .unwrap();
    send(&mut svm, &payer, &[&payer, &mint], &[create, init]);

    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    assert_eq!(err, ClearingError::UnsupportedMint as u32);
}

fn freeze_ix(signer: Pubkey) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new_readonly(signer, true),
            AccountMeta::new(config, false),
        ],
        data: instruction::pack_freeze().to_vec(),
    }
}

fn encode_proof(mask: u128, siblings: &[[u8; 32]], leaf: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + siblings.len() * 32 + leaf.len());
    out.extend_from_slice(&mask.to_le_bytes());
    out.push(siblings.len() as u8);
    for s in siblings {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(leaf);
    out
}

fn merkle_leaf(
    account_id: [u8; 16],
    owner: [u8; 32],
    asset: u32,
    amount: i128,
    n_siblings: u8,
) -> ([u8; 32], Vec<u8>) {
    let mut acc = Account::new();
    acc.credit(AssetId(asset), Amount(amount)).unwrap();
    acc.set_l1_owner(L1Address(owner)).unwrap();
    let key = u128::from_be_bytes(account_id);
    let mut tree = StateTree::new(Sha256Hasher);
    tree.update_account(AccountId(Uuid::from_u128(key)), Some(&acc));
    for i in 0..n_siblings {
        let mut other = Account::new();
        other.credit(AssetId(asset), Amount(1)).unwrap();
        other.set_l1_owner(L1Address([0xFFu8; 32])).unwrap();
        tree.update_account(AccountId(Uuid::from_u128(key ^ (1u128 << i))), Some(&other));
    }
    let (mask, sibs) = tree.prove(AccountId(Uuid::from_u128(key)));
    assert_eq!(sibs.len(), n_siblings as usize, "sibling count");
    let leaf = canonical_encode(&acc);
    (tree.root(), encode_proof(mask, &sibs, &leaf))
}

fn write_account(svm: &mut LiteSVM, key: Pubkey, owner: Pubkey, data: Vec<u8>) {
    let lamports = svm.minimum_balance_for_rent_exemption(data.len()).max(1);
    svm.set_account(
        key,
        SolAccount {
            lamports,
            data,
            owner,
            executable: false,
            rent_epoch: 0,
        },
    )
    .unwrap();
}

fn escape_ix(
    owner: Pubkey,
    owner_ata: Pubkey,
    mint: Pubkey,
    proof_buffer: Pubkey,
    args: EscapeWithdrawArgs,
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (mint_meta, _) = pda::find_mint_meta(&PROGRAM_ID, mint.as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.as_array());
    let (escape_nullifier, _) =
        pda::find_escape_nullifier(&PROGRAM_ID, owner.as_array(), mint.as_array());
    let (vault_authority, _) = pda::find_vault_authority(&PROGRAM_ID);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(owner, true),
            AccountMeta::new(owner_ata, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(mint_meta, false),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new_readonly(proof_buffer, false),
            AccountMeta::new(escape_nullifier, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(vault_authority, false),
        ],
        data: args.pack().to_vec(),
    }
}

fn funded_vault(
    svm: &mut LiteSVM,
    payer: &Keypair,
    admin: &Keypair,
    amount: u64,
) -> (Pubkey, Keypair, Pubkey) {
    let config = initialize(svm, payer, admin.pubkey());
    let mint = create_token_2022_mint(svm, payer, &payer.pubkey());
    send(
        svm,
        admin,
        &[admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.pubkey().as_array());
    mint_to(svm, payer, payer, &mint.pubkey(), &vault, amount);
    (config, mint, vault)
}

#[test]
fn freeze_ix_blocks_deposit() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let mint = create_token_2022_mint(&mut svm, &payer, &payer.pubkey());
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[register_mint_ix(admin.pubkey(), mint.pubkey(), DECIMALS)],
    );
    send(&mut svm, &admin, &[&admin], &[freeze_ix(admin.pubkey())]);
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.frozen, 1);

    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 1_000);
    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[deposit_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            DepositArgs {
                account_id: ACCOUNT_ID,
                amount: 1_000,
                trading_key: None,
            },
        )],
    );
    assert_eq!(err, ClearingError::Frozen as u32);
}

#[test]
fn freeze_authority_can_freeze() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    let freeze_authority = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    airdrop(&mut svm, &freeze_authority.pubkey());

    let (config, _) = pda::find_config(&PROGRAM_ID);
    let vk_account = Pubkey::new_from_array([9u8; 32]);
    let mut args = init_args(admin.pubkey());
    args.freeze_authority = *freeze_authority.pubkey().as_array();
    let ix = Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(payer.pubkey(), true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: args.pack().to_vec(),
    };
    send(&mut svm, &payer, &[&payer], &[ix]);

    send(
        &mut svm,
        &freeze_authority,
        &[&freeze_authority],
        &[freeze_ix(freeze_authority.pubkey())],
    );
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.frozen, 1);
}

fn escape_once(
    svm: &mut LiteSVM,
    admin: &Keypair,
    user: &Keypair,
    ata: &Keypair,
    mint: &Keypair,
    n_siblings: u8,
    amount: u64,
) -> u64 {
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.pubkey().as_array());
    let (root, proof) = merkle_leaf(
        ACCOUNT_ID,
        *user.pubkey().as_array(),
        0,
        amount as i128,
        n_siblings,
    );
    let (config, _) = pda::find_config(&PROGRAM_ID);
    poke_config(svm, &config, |cfg| {
        cfg.root = root;
    });
    send(svm, admin, &[admin], &[freeze_ix(admin.pubkey())]);

    let buffer = Keypair::new();
    write_account(svm, buffer.pubkey(), user.pubkey(), proof);

    let args = EscapeWithdrawArgs {
        account_id: ACCOUNT_ID,
        asset_id: 0,
    };
    let vault_before = token_amount(svm, &vault);
    let ata_before = token_amount(svm, &ata.pubkey());
    let cu = send_ok(
        svm,
        user,
        &[user],
        &[escape_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            buffer.pubkey(),
            args,
        )],
    );
    assert_eq!(token_amount(svm, &ata.pubkey()), ata_before + amount);
    assert_eq!(token_amount(svm, &vault), vault_before - amount);
    let (nullifier, bump) = pda::find_escape_nullifier(
        &PROGRAM_ID,
        user.pubkey().as_array(),
        mint.pubkey().as_array(),
    );
    let n = Nullifier::unpack(&svm.get_account(&nullifier).unwrap().data).unwrap();
    assert_eq!(n.bump, bump);
    cu
}

#[test]
fn escape_withdraw_pays_leaf_owner() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (_config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    assert_eq!(token_amount(&svm, &ata.pubkey()), 0);
    assert_eq!(token_amount(&svm, &vault), amount);

    let cu = escape_once(&mut svm, &admin, &user, &ata, &mint, 0, amount);
    assert!(cu < 200_000, "escape CU {cu}");
}

#[test]
fn escape_rejects_theft_of_another_leaf() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (owner_b, _ata_b) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    let (thief, thief_ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);

    let account_b: [u8; 16] = [0x05; 16];
    let (root, proof) = merkle_leaf(
        account_b,
        *owner_b.pubkey().as_array(),
        0,
        amount as i128,
        0,
    );
    poke_config(&mut svm, &config, |cfg| {
        cfg.root = root;
        cfg.frozen = 1;
    });
    let buffer = Keypair::new();
    write_account(&mut svm, buffer.pubkey(), thief.pubkey(), proof);

    let vault_before = token_amount(&svm, &vault);
    let err = send_custom_err(
        &mut svm,
        &thief,
        &[&thief],
        &[escape_ix(
            thief.pubkey(),
            thief_ata.pubkey(),
            mint.pubkey(),
            buffer.pubkey(),
            EscapeWithdrawArgs {
                account_id: account_b,
                asset_id: 0,
            },
        )],
    );
    assert_eq!(err, ClearingError::OwnerMismatch as u32);
    assert_eq!(token_amount(&svm, &vault), vault_before);
    assert_eq!(token_amount(&svm, &thief_ata.pubkey()), 0);
}

#[test]
fn escape_requires_frozen() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    let (root, proof) = merkle_leaf(ACCOUNT_ID, *user.pubkey().as_array(), 0, amount as i128, 0);
    poke_config(&mut svm, &config, |cfg| {
        cfg.root = root;
    });
    let buffer = Keypair::new();
    write_account(&mut svm, buffer.pubkey(), user.pubkey(), proof);

    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[escape_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            buffer.pubkey(),
            EscapeWithdrawArgs {
                account_id: ACCOUNT_ID,
                asset_id: 0,
            },
        )],
    );
    assert_eq!(err, ClearingError::InvalidAccount as u32);
    assert_eq!(token_amount(&svm, &vault), amount);
}

#[test]
fn escape_24_and_40_siblings() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 500u64;
    let (_config, mint, _vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    let cu24 = escape_once(&mut svm, &admin, &user, &ata, &mint, 24, amount);
    assert!(cu24 < 200_000, "24-sibling CU {cu24}");

    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let (_config, mint, _vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    let cu40 = escape_once(&mut svm, &admin, &user, &ata, &mint, 40, amount);
    assert!(cu40 < 200_000, "40-sibling CU {cu40}");
}

#[test]
fn escape_rejects_double_claim() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (_config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount * 2);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    escape_once(&mut svm, &admin, &user, &ata, &mint, 0, amount);

    mint_to(&mut svm, &payer, &payer, &mint.pubkey(), &vault, amount);
    let (root, proof) = merkle_leaf(ACCOUNT_ID, *user.pubkey().as_array(), 0, amount as i128, 0);
    let (config, _) = pda::find_config(&PROGRAM_ID);
    poke_config(&mut svm, &config, |cfg| {
        cfg.root = root;
    });
    let buffer = Keypair::new();
    write_account(&mut svm, buffer.pubkey(), user.pubkey(), proof);
    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[escape_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            buffer.pubkey(),
            EscapeWithdrawArgs {
                account_id: ACCOUNT_ID,
                asset_id: 0,
            },
        )],
    );
    assert_eq!(err, ClearingError::AlreadyInitialized as u32);
}

#[test]
fn escape_rejects_invalid_proof_buffer() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (config, mint, _vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    poke_config(&mut svm, &config, |cfg| {
        cfg.frozen = 1;
    });
    let mut bad = vec![0u8; 17];
    bad[16] = 129;
    let buffer = Keypair::new();
    write_account(&mut svm, buffer.pubkey(), user.pubkey(), bad);
    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[escape_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            buffer.pubkey(),
            EscapeWithdrawArgs {
                account_id: ACCOUNT_ID,
                asset_id: 0,
            },
        )],
    );
    assert_eq!(err, ClearingError::InvalidProofBuffer as u32);
}

fn settle_ix(
    admin: Pubkey,
    vk_account: Pubkey,
    batch_seq: u64,
    prev_root: [u8; 32],
    new_root: [u8; 32],
    withdrawals_root: [u8; 32],
    matcher_key: [u8; 32],
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (batch, _) = pda::find_batch(&PROGRAM_ID, &batch_seq.to_le_bytes());
    let args = SettleArgs {
        proof: [0u8; SETTLE_PROOF_LEN],
        public_values: pack_public_values(
            &prev_root,
            &new_root,
            &withdrawals_root,
            &matcher_key,
            batch_seq,
            0,
        ),
        da_hash: [0xDDu8; 32],
    };
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new(batch, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: args.pack().to_vec(),
    }
}

fn claim_ix(
    claimant: Pubkey,
    claimant_ata: Pubkey,
    mint: Pubkey,
    batch_seq: u64,
    index: u32,
    asset_id: u32,
    amount: u64,
    siblings: &[[u8; 32]],
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (mint_meta, _) = pda::find_mint_meta(&PROGRAM_ID, mint.as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.as_array());
    let (batch, _) = pda::find_batch(&PROGRAM_ID, &batch_seq.to_le_bytes());
    let (vault_authority, _) = pda::find_vault_authority(&PROGRAM_ID);
    let owner = *claimant.as_array();
    let amt = Amount(amount as i128).to_le_bytes();
    let leaf =
        clearing_solana_program::hash::withdrawal_leaf(batch_seq, index, &owner, asset_id, &amt);
    let (nullifier, _) = pda::find_claim_nullifier(&PROGRAM_ID, &leaf);
    let header = ClaimArgs {
        batch_seq,
        index,
        asset_id,
        amount,
        n_siblings: siblings.len() as u8,
    }
    .pack_header();
    let mut data = header.to_vec();
    for s in siblings {
        data.extend_from_slice(s);
    }
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(claimant, true),
            AccountMeta::new(claimant_ata, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(mint_meta, false),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new_readonly(batch, false),
            AccountMeta::new(nullifier, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(vault_authority, false),
        ],
        data,
    }
}

const VK_ACCOUNT: [u8; 32] = [9u8; 32];

#[test]
fn claim_pays_once_and_rejects_replay_and_bad_amount() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let amount = 1_000u64;
    let (config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);

    let owner = L1Address(*user.pubkey().as_array());
    let entries = [(owner, AssetId(0), Amount(amount as i128))];
    let hasher = Sha256Hasher;
    let w_root = withdrawals_root(&hasher, 0, &entries);
    let siblings = withdrawal_proof(&hasher, 0, &entries, 0);

    let genesis = Config::unpack(&svm.get_account(&config).unwrap().data)
        .unwrap()
        .root;
    let matcher = init_args(admin.pubkey()).matcher_key;
    let vk = Pubkey::new_from_array(VK_ACCOUNT);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix(
            admin.pubkey(),
            vk,
            0,
            genesis,
            [0xAAu8; 32],
            w_root,
            matcher,
        )],
    );

    let rec = BatchRecord::unpack(
        &svm.get_account(&pda::find_batch(&PROGRAM_ID, &0u64.to_le_bytes()).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(rec.withdrawals_root, w_root);

    let vault_before = token_amount(&svm, &vault);
    send_ok(
        &mut svm,
        &user,
        &[&user],
        &[claim_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            0,
            0,
            amount,
            &siblings,
        )],
    );
    assert_eq!(token_amount(&svm, &ata.pubkey()), amount);
    assert_eq!(token_amount(&svm, &vault), vault_before - amount);

    svm.expire_blockhash();
    let replay = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[claim_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            0,
            0,
            amount,
            &siblings,
        )],
    );
    assert_eq!(replay, ClearingError::AlreadyInitialized as u32);

    // Fresh svm for bad-amount: settle same root, wrong amount fails inclusion.
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let (_config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);
    let (user, ata) = funded_user(&mut svm, &payer, &mint.pubkey(), 0);
    let owner = L1Address(*user.pubkey().as_array());
    let entries = [(owner, AssetId(0), Amount(amount as i128))];
    let w_root = withdrawals_root(&Sha256Hasher, 0, &entries);
    let siblings = withdrawal_proof(&Sha256Hasher, 0, &entries, 0);
    let genesis = [0x11u8; 32];
    let matcher = init_args(admin.pubkey()).matcher_key;
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix(
            admin.pubkey(),
            Pubkey::new_from_array(VK_ACCOUNT),
            0,
            genesis,
            [0xAAu8; 32],
            w_root,
            matcher,
        )],
    );
    let vault_before = token_amount(&svm, &vault);
    let err = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[claim_ix(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            0,
            0,
            0,
            amount + 1,
            &siblings,
        )],
    );
    assert_eq!(err, ClearingError::InvalidProof as u32);
    assert_eq!(token_amount(&svm, &vault), vault_before);
}

#[test]
fn set_admin_rotates_without_touching_matcher_key() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    let new_admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    airdrop(&mut svm, &new_admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let matcher = Config::unpack(&svm.get_account(&config).unwrap().data)
        .unwrap()
        .matcher_key;

    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SetAdminArgs {
                new_admin: *new_admin.pubkey().as_array(),
            }
            .pack()
            .to_vec(),
        }],
    );
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.admin, *new_admin.pubkey().as_array());
    assert_eq!(cfg.matcher_key, matcher);

    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
            ],
            data: SetAdminArgs {
                new_admin: *admin.pubkey().as_array(),
            }
            .pack()
            .to_vec(),
        }],
    );
    assert_eq!(err, ClearingError::Unauthorized as u32);
}

#[test]
fn rotate_vk_updates_config_fields() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());

    let config = initialize(&mut svm, &payer, admin.pubkey());
    let new_vk = Pubkey::new_from_array([0xEEu8; 32]);
    write_account(&mut svm, new_vk, PROGRAM_ID, vec![0u8; 8]);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
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
        }],
    );
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.vk_account, *new_vk.as_array());
    assert_eq!(cfg.guest_vk_hash, [0x11u8; 32]);
    assert_eq!(cfg.groth16_vk_hash_prefix, [1, 2, 3, 4]);
    assert_eq!(cfg.proof_version, 1);
}

/// proof_version=1 always pairs. Zeros fail the gnark-vk prefix check.
#[test]
fn settle_wrap_rejects_junk_when_proof_version_is_1() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let config = initialize(&mut svm, &payer, admin.pubkey());

    let mut vk_data = vec![0u8; 452 + 3 * 64];
    vk_data[0..4].copy_from_slice(&2u32.to_le_bytes());
    let new_vk = Pubkey::new_from_array([0xEEu8; 32]);
    write_account(&mut svm, new_vk, PROGRAM_ID, vk_data);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
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
        }],
    );

    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix(
            admin.pubkey(),
            new_vk,
            0,
            cfg.root,
            [0xAAu8; 32],
            [0xBBu8; 32],
            cfg.matcher_key,
        )],
    );
    assert_eq!(err, ClearingError::InvalidProof as u32);
    let after = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(after.root, cfg.root);
    assert_eq!(after.batch_seq, 0);
}

#[test]
fn settle_circuits_rejects_junk_when_proof_version_is_2() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let config = initialize(&mut svm, &payer, admin.pubkey());

    let mut vk_data = vec![0u8; 452 + 2 * 64];
    vk_data[0..4].copy_from_slice(&1u32.to_le_bytes());
    let new_vk = Pubkey::new_from_array([0xCCu8; 32]);
    write_account(&mut svm, new_vk, PROGRAM_ID, vk_data);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(new_vk, false),
            ],
            data: RotateVkArgs {
                guest_vk_hash: [0u8; 32],
                groth16_vk_hash_prefix: [0; 4],
                proof_version: 2,
            }
            .pack()
            .to_vec(),
        }],
    );

    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    let err = send_custom_err(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix(
            admin.pubkey(),
            new_vk,
            0,
            cfg.root,
            [0xAAu8; 32],
            [0xBBu8; 32],
            cfg.matcher_key,
        )],
    );
    assert_eq!(err, ClearingError::InvalidProof as u32);
}

fn pubkey_lt_fr(pk: &Pubkey) -> bool {
    pk.as_array().as_slice() < &FR_MODULUS_BE[..]
}

const FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

fn user_in_fr() -> Keypair {
    loop {
        let k = Keypair::new();
        if pubkey_lt_fr(&k.pubkey()) {
            return k;
        }
    }
}

fn prove_claim_open_for(
    owner: &[u8; 32],
    asset: u32,
    amount: u64,
) -> (Vec<u8>, [u8; PROOF_LEN], [u8; 32]) {
    let mut rng = StdRng::seed_from_u64(21);
    let owner_fr = Fr::from_be_bytes_mod_order(owner);
    let asset_fr = Fr::from(asset as u64);
    let amount_fr = Fr::from(amount);
    let leaf = clearing_circuits::claim_open_leaf(owner_fr, asset_fr, amount_fr);
    let mut leaves: Vec<Fr> = (0..(1u64 << CIRCUITS_DEPTH)).map(Fr::from).collect();
    leaves[0] = leaf;
    let tree = MerkleTree::new(leaves);
    let root = tree.root();
    let (siblings, bits) = tree.path(0);
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(ClaimOpenCircuit::blank(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(
        &pk,
        ClaimOpenCircuit::new(root, owner_fr, asset_fr, amount_fr, siblings, bits),
        &mut rng,
    )
    .unwrap();
    (
        encode_vk_account(&circuits_solana::vk_to_bytes(&vk)).unwrap(),
        circuits_solana::proof_to_bytes(&proof),
        circuits_solana::public_input_to_bytes(&root),
    )
}

fn claim_ix_circuits(
    claimant: Pubkey,
    claimant_ata: Pubkey,
    mint: Pubkey,
    open_vk: Pubkey,
    batch_seq: u64,
    amount: u64,
    proof: &[u8; PROOF_LEN],
) -> Instruction {
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (mint_meta, _) = pda::find_mint_meta(&PROGRAM_ID, mint.as_array());
    let (vault, _) = pda::find_vault(&PROGRAM_ID, mint.as_array());
    let (batch, _) = pda::find_batch(&PROGRAM_ID, &batch_seq.to_le_bytes());
    let (vault_authority, _) = pda::find_vault_authority(&PROGRAM_ID);
    let owner = *claimant.as_array();
    let amt = Amount(amount as i128).to_le_bytes();
    let leaf = clearing_solana_program::hash::withdrawal_leaf(batch_seq, 0, &owner, 0, &amt);
    let (nullifier, _) = pda::find_claim_nullifier(&PROGRAM_ID, &leaf);
    let header = ClaimArgs {
        batch_seq,
        index: 0,
        asset_id: 0,
        amount,
        n_siblings: 0,
    }
    .pack_header();
    let mut data = header.to_vec();
    data.extend_from_slice(proof);
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(claimant, true),
            AccountMeta::new(claimant_ata, false),
            AccountMeta::new(vault, false),
            AccountMeta::new_readonly(mint, false),
            AccountMeta::new_readonly(mint_meta, false),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new_readonly(batch, false),
            AccountMeta::new(nullifier, false),
            AccountMeta::new_readonly(TOKEN_2022, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
            AccountMeta::new_readonly(vault_authority, false),
            AccountMeta::new_readonly(open_vk, false),
        ],
        data,
    }
}

#[test]
fn claim_v2_pays_vault_once() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let amount = 1_000u64;
    let (config, mint, vault) = funded_vault(&mut svm, &payer, &admin, amount);

    let user = user_in_fr();
    airdrop(&mut svm, &user.pubkey());
    let ata = create_token_account(&mut svm, &payer, &mint.pubkey(), &user.pubkey());

    let (open_vk_data, proof, w_root) =
        prove_claim_open_for(user.pubkey().as_array(), 0, amount);
    let open_vk = Pubkey::new_from_array([0x0Au8; 32]);
    write_account(&mut svm, open_vk, PROGRAM_ID, open_vk_data);

    let genesis = Config::unpack(&svm.get_account(&config).unwrap().data)
        .unwrap()
        .root;
    let matcher = init_args(admin.pubkey()).matcher_key;
    let settle_vk = Pubkey::new_from_array(VK_ACCOUNT);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix(
            admin.pubkey(),
            settle_vk,
            0,
            genesis,
            genesis,
            w_root,
            matcher,
        )],
    );

    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(open_vk, false),
            ],
            data: pack_rotate_open_vk().to_vec(),
        }],
    );
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(settle_vk, false),
            ],
            data: RotateVkArgs {
                guest_vk_hash: [0u8; 32],
                groth16_vk_hash_prefix: [0; 4],
                proof_version: PROOF_VERSION_CIRCUITS,
            }
            .pack()
            .to_vec(),
        }],
    );

    let vault_before = token_amount(&svm, &vault);
    send_ok(
        &mut svm,
        &user,
        &[&user],
        &[claim_ix_circuits(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            open_vk,
            0,
            amount,
            &proof,
        )],
    );
    assert_eq!(token_amount(&svm, &ata.pubkey()), amount);
    assert_eq!(token_amount(&svm, &vault), vault_before - amount);

    svm.expire_blockhash();
    let replay = send_custom_err(
        &mut svm,
        &user,
        &[&user],
        &[claim_ix_circuits(
            user.pubkey(),
            ata.pubkey(),
            mint.pubkey(),
            open_vk,
            0,
            amount,
            &proof,
        )],
    );
    assert_eq!(replay, ClearingError::AlreadyInitialized as u32);
}

fn prove_commit_roots(
    prev: &[u8; 32],
    new: &[u8; 32],
    withdrawals: &[u8; 32],
) -> (Vec<u8>, [u8; PROOF_LEN]) {
    let mut rng = StdRng::seed_from_u64(5);
    let prev_fr = Fr::from_be_bytes_mod_order(prev);
    let new_fr = Fr::from_be_bytes_mod_order(new);
    let w_fr = Fr::from_be_bytes_mod_order(withdrawals);
    let (pk, vk) =
        Groth16::<Bn254>::circuit_specific_setup(CommitRootsCircuit::blank(), &mut rng).unwrap();
    let proof = Groth16::<Bn254>::prove(
        &pk,
        CommitRootsCircuit::new(prev_fr, new_fr, w_fr),
        &mut rng,
    )
    .unwrap();
    (
        encode_vk_account(&circuits_solana::vk_to_bytes(&vk)).unwrap(),
        circuits_solana::proof_to_bytes(&proof),
    )
}

fn settle_ix_circuits(
    admin: Pubkey,
    vk_account: Pubkey,
    batch_seq: u64,
    prev_root: [u8; 32],
    new_root: [u8; 32],
    withdrawals_root: [u8; 32],
    matcher_key: [u8; 32],
    proof: &[u8; PROOF_LEN],
) -> Instruction {
    let mut wrap = [0u8; SETTLE_PROOF_LEN];
    wrap[..PROOF_LEN].copy_from_slice(proof);
    let (config, _) = pda::find_config(&PROGRAM_ID);
    let (batch, _) = pda::find_batch(&PROGRAM_ID, &batch_seq.to_le_bytes());
    let args = SettleArgs {
        proof: wrap,
        public_values: pack_public_values(
            &prev_root,
            &new_root,
            &withdrawals_root,
            &matcher_key,
            batch_seq,
            0,
        ),
        da_hash: [0xDDu8; 32],
    };
    Instruction {
        program_id: PROGRAM_ID,
        accounts: vec![
            AccountMeta::new(admin, true),
            AccountMeta::new(config, false),
            AccountMeta::new_readonly(vk_account, false),
            AccountMeta::new(batch, false),
            AccountMeta::new_readonly(solana_system_interface::program::ID, false),
        ],
        data: args.pack().to_vec(),
    }
}

#[test]
fn settle_v2_posts_withdrawals_root() {
    let mut svm = setup_svm();
    let payer = Keypair::new();
    let admin = Keypair::new();
    airdrop(&mut svm, &payer.pubkey());
    airdrop(&mut svm, &admin.pubkey());
    let config = initialize(&mut svm, &payer, admin.pubkey());
    let genesis = [0x11u8; 32];
    let w_root = [0x22u8; 32];
    let (vk_data, proof) = prove_commit_roots(&genesis, &genesis, &w_root);
    let settle_vk = Pubkey::new_from_array([0x51u8; 32]);
    write_account(&mut svm, settle_vk, PROGRAM_ID, vk_data);
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[Instruction {
            program_id: PROGRAM_ID,
            accounts: vec![
                AccountMeta::new_readonly(admin.pubkey(), true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(settle_vk, false),
            ],
            data: RotateVkArgs {
                guest_vk_hash: [0u8; 32],
                groth16_vk_hash_prefix: [0; 4],
                proof_version: PROOF_VERSION_CIRCUITS,
            }
            .pack()
            .to_vec(),
        }],
    );
    let matcher = init_args(admin.pubkey()).matcher_key;
    send(
        &mut svm,
        &admin,
        &[&admin],
        &[settle_ix_circuits(
            admin.pubkey(),
            settle_vk,
            0,
            genesis,
            genesis,
            w_root,
            matcher,
            &proof,
        )],
    );
    let cfg = Config::unpack(&svm.get_account(&config).unwrap().data).unwrap();
    assert_eq!(cfg.root, genesis);
    assert_eq!(cfg.batch_seq, 1);
    let rec = BatchRecord::unpack(
        &svm.get_account(&pda::find_batch(&PROGRAM_ID, &0u64.to_le_bytes()).0)
            .unwrap()
            .data,
    )
    .unwrap();
    assert_eq!(rec.withdrawals_root, w_root);
}
