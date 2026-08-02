use std::time::Duration;

use anyhow::anyhow;
use clap::{Args, Subcommand};
use minicbor::data::{Int, Tag};
use qrcode::{QrCode, render::unicode};
use rand::rngs::OsRng;
use tokio::io::{AsyncWriteExt, stdout};
use uuid::Uuid;
use zcash_client_backend::data_api::Account;
use zcash_client_sqlite::{WalletDb, util::SystemClock};

use crate::{ShutdownListener, config::WalletConfig, data::get_db_paths};

use super::select_account;

const ZCASH_ACCOUNTS: &str = "zcash-accounts";

#[cfg(feature = "pczt-qr")]
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Emulate the Keystone enrollment protocol
    Enroll(Enroll),
}

// Options accepted for the `keystone enroll` command
#[derive(Debug, Args)]
pub(crate) struct Enroll {
    /// The UUID of the account to enroll
    account_id: Option<Uuid>,

    /// The duration in milliseconds to wait between QR codes (default is 500)
    #[arg(long)]
    #[arg(default_value_t = 500)]
    interval: u64,
}

impl Enroll {
    pub(crate) async fn run(
        self,
        mut shutdown: ShutdownListener,
        wallet_dir: Option<String>,
    ) -> Result<(), anyhow::Error> {
        let config = WalletConfig::read(wallet_dir.as_ref())?;
        let params = config.network();

        let (_, db_data) = get_db_paths(wallet_dir.as_ref());
        let db_data = WalletDb::for_path(db_data, params, SystemClock, OsRng)?;
        let account = select_account(&db_data, self.account_id)?;

        let key_derivation = account
            .source()
            .key_derivation()
            .ok_or(anyhow!("Cannot enroll account without spending key"))?;

        let mut accounts_packet = vec![];
        minicbor::encode(
            &ZcashAccounts {
                seed_fingerprint: key_derivation.seed_fingerprint().to_bytes(),
                accounts: vec![ZcashUnifiedFullViewingKey {
                    ufvk: account
                        .ufvk()
                        .ok_or(anyhow!("Cannot enroll account without UFVK"))?
                        .encode(&params),
                    index: key_derivation.account_index().into(),
                    name: account.name().map(String::from),
                }],
            },
            &mut accounts_packet,
        )
        .map_err(|e| anyhow!("Failed to encode accounts packet: {:?}", e))?;

        let mut encoder = ur::Encoder::new(&accounts_packet, 100, ZCASH_ACCOUNTS)
            .map_err(|e| anyhow!("Failed to build UR encoder: {e}"))?;

        let mut stdout = stdout();
        let mut interval = tokio::time::interval(Duration::from_millis(self.interval));
        loop {
            interval.tick().await;

            if shutdown.requested() {
                return Ok(());
            }

            let ur = encoder
                .next_part()
                .map_err(|e| anyhow!("Failed to encode PCZT part: {e}"))?;
            let code = QrCode::new(ur.to_uppercase())?;
            let string = code
                .render::<unicode::Dense1x2>()
                .dark_color(unicode::Dense1x2::Light)
                .light_color(unicode::Dense1x2::Dark)
                .quiet_zone(true)
                .build();

            stdout.write_all(format!("{string}\n").as_bytes()).await?;
            stdout.write_all(format!("{ur}\n\n\n\n").as_bytes()).await?;
            stdout.flush().await?;
        }
    }
}

struct ZcashAccounts {
    seed_fingerprint: [u8; 32],
    accounts: Vec<ZcashUnifiedFullViewingKey>,
}

struct ZcashUnifiedFullViewingKey {
    ufvk: String,
    index: u32,
    name: Option<String>,
}

const SEED_FINGERPRINT: u8 = 1;
const ACCOUNTS: u8 = 2;
const ZCASH_UNIFIED_FULL_VIEWING_KEY: u64 = 49203;
const UFVK: u8 = 1;
const INDEX: u8 = 2;
const NAME: u8 = 3;

impl<C> minicbor::Encode<C> for ZcashAccounts {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2)?;

        e.int(Int::from(SEED_FINGERPRINT))?
            .bytes(&self.seed_fingerprint)?;

        e.int(Int::from(ACCOUNTS))?
            .array(self.accounts.len() as u64)?;
        for account in &self.accounts {
            e.tag(Tag::new(ZCASH_UNIFIED_FULL_VIEWING_KEY))?;
            ZcashUnifiedFullViewingKey::encode(account, e, _ctx)?;
        }

        Ok(())
    }
}

impl<C> minicbor::Encode<C> for ZcashUnifiedFullViewingKey {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.map(2 + u64::from(self.name.is_some()))?;

        e.int(Int::from(UFVK))?.str(&self.ufvk)?;
        e.int(Int::from(INDEX))?.u32(self.index)?;

        if let Some(name) = &self.name {
            e.int(Int::from(NAME))?.str(name)?;
        }

        Ok(())
    }
}

/// The `zcash-accounts` CBOR and UR encodings below are the wire format the
/// `keystone enroll` command shares with Keystone hardware wallets: a changed
/// byte here means a device no longer recognises an enrollment QR, so these
/// vectors pin the encoding rather than exercising the codec against itself.
///
/// The expected values were captured from this same encoder as it existed
/// before the `minicbor` 0.19 -> 2 / `ur` 0.4 -> 0.5 migration (in particular
/// `Tag::Unassigned(49203)` -> `Tag::new(49203)`), by compiling it against the
/// old crate pair. They must never change.
#[cfg(test)]
mod wire_format_tests {
    use super::*;

    /// Deterministic stand-in for an encoded UFVK: same `uview1` HRP and
    /// typical length (280 chars) as a real mainnet UFVK, built from the
    /// bech32 alphabet. The encoder treats it as an opaque string.
    fn sample_ufvk() -> String {
        const ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        let tail: String = (0..274)
            .map(|i| ALPHABET[(i * 7) % ALPHABET.len()] as char)
            .collect();
        format!("uview1{tail}")
    }

    /// Two accounts so both map shapes are pinned: one with the optional
    /// `name` entry (a 3-entry map) and one without (a 2-entry map). The
    /// multi-byte account index pins the u32 encoding beyond the one-byte
    /// small-int range.
    fn sample_accounts() -> ZcashAccounts {
        ZcashAccounts {
            seed_fingerprint: core::array::from_fn(|i| i as u8),
            accounts: vec![
                ZcashUnifiedFullViewingKey {
                    ufvk: sample_ufvk(),
                    index: 0x0102_0304,
                    name: Some("Keystone enrollment fixture".into()),
                },
                ZcashUnifiedFullViewingKey {
                    ufvk: sample_ufvk(),
                    index: 0,
                    name: None,
                },
            ],
        }
    }

    const EXPECTED_ACCOUNTS_CBOR: &str = "a2015820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0282d9c033a3017901187576696577317138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a667368021a0102030403781b4b657973746f6e6520656e726f6c6c6d656e742066697874757265d9c033a2017901187576696577317138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673683739766e367067306b6179746a657138773475723233636c7864356d7a6673680200";

    /// Eight consecutive parts: the seven that carry the payload, plus one
    /// fountain-combined part, which exercises the XOR path as well.
    const EXPECTED_UR_PARTS: &[&str] = &[
        "ur:zcash-accounts/1-7/lpadatcfaolkcyhkzsvegshdhyoeadhdcxaeadaoaxaaahamatayasbkbdbnbtbabsbebybgbwbbbzcmchcscfcycwcecackctaolftarteootadkkadcskpkoinihktehjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzeotsluhd",
        "ur:zcash-accounts/2-7/lpaoatcfaolkcyhkzsvegshdhyksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoemtkhkfm",
        "ur:zcash-accounts/3-7/lpaxatcfaolkcyhkzsvegshdhyiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpesnnjtfs",
        "ur:zcash-accounts/4-7/lpaaatcfaolkcyhkzsvegshdhyeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisaocyadaoaxaaaxkscwgrihkkjkjyjljtihcxihjtjpjljzjzjnihjtjycxiyinksjykpjpihtarteooeadkkadcskpkoinihktehurtbwzey",
        "ur:zcash-accounts/5-7/lpahatcfaolkcyhkzsvegshdhyjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyvepylycx",
        "ur:zcash-accounts/6-7/lpamatcfaolkcyhkzsvegshdhyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehsosknwflr",
        "ur:zcash-accounts/7-7/lpatatcfaolkcyhkzsvegshdhykkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisemeskojtenjoiodyjehskkjyimihjsetkteekpjpeyeoiajzksieecjnkniyjkisaoaeaeaeaeaeaeaekoetimkp",
        "ur:zcash-accounts/8-7/lpayatcfaolkcyhkzsvegshdhygdcybsahbdcyahcshygrhtgucfhhfpadbkbwhkathkhybagugtgrgrcfaobybtaogdcybsahbdcyahcshygrhtgudwlbenjnfhiofsgwdtjybghyghhtgogwbeahcackbefgaeahckcwhyadaagrfzfxhtbefebkvwotbtmdeofgfxamdkeniheeihdkjpiekski",
    ];

    #[test]
    fn zcash_accounts_cbor_encoding_is_unchanged() {
        let mut packet = vec![];
        minicbor::encode(sample_accounts(), &mut packet).expect("encoding succeeds");
        assert_eq!(hex::encode(&packet), EXPECTED_ACCOUNTS_CBOR);
    }

    /// The registry tag is what lets Keystone firmware recognise each UFVK
    /// entry; `Tag::new(49203)` must keep lowering to the same bytes that
    /// `Tag::Unassigned(49203)` produced (0xd9 0xc0 0x33).
    #[test]
    fn zcash_unified_full_viewing_key_tag_is_unchanged() {
        let mut packet = vec![];
        minicbor::encode(sample_accounts(), &mut packet).expect("encoding succeeds");
        let tag_bytes = [0xd9, 0xc0, 0x33];
        let count = packet
            .windows(tag_bytes.len())
            .filter(|w| *w == tag_bytes)
            .count();
        assert_eq!(count, 2, "expected tag 49203 once per account entry");
    }

    #[test]
    fn zcash_accounts_ur_fragmentation_is_unchanged() {
        let mut packet = vec![];
        minicbor::encode(sample_accounts(), &mut packet).expect("encoding succeeds");

        let mut encoder =
            ur::Encoder::new(&packet, 100, ZCASH_ACCOUNTS).expect("UR encoder builds");
        let parts: Vec<String> = (0..EXPECTED_UR_PARTS.len())
            .map(|_| encoder.next_part().expect("part encodes"))
            .collect();

        assert_eq!(parts, EXPECTED_UR_PARTS);
    }
}
