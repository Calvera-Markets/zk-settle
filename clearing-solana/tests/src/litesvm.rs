use ::litesvm::LiteSVM;
use clearing_solana_program::{
    error::ClearingError,
    instruction::{DepositArgs, InitializeArgs, RegisterMintArgs},
    pda,
    state::{AccountOwner, Config, DepositReceipt, MintMeta},
    ID as PROGRAM_ID,
};
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

const DECIMALS: u8 = 6;
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
    mint_to(svm, payer, payer, mint, &ata.pubkey(), amount);
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
