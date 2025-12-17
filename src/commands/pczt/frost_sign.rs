use std::collections::HashMap;

use anyhow::anyhow;
use orchard::primitives::redpallas::{self, SpendAuth};
use pczt::{roles::low_level_signer::Signer, Pczt};
use tokio::io::{stdin, stdout, AsyncReadExt, AsyncWriteExt};

use group::ff::PrimeField;
use zcash_primitives::transaction::{sighash::SignableInput, txid::TxIdDigester};
use zcash_primitives::transaction::{sighash_v5::v5_signature_hash, TxVersion};

use frost_client::api::PublicKey;

// Options accepted for the `pczt frost-sign` command
#[derive(Debug, clap::Args)]
pub(crate) struct Command {
    /// The path to the config file to manage. If not specified, it uses
    /// $HOME/.local/frost/credentials.toml
    #[arg(short, long)]
    pub config: Option<String>,
    /// The server URL to use. If not specified, it will use the server URL
    /// for the specified group, if any.
    #[arg(short, long)]
    pub server_url: Option<String>,
    /// The group to use, identified by the group public key (use `groups`
    /// to list)
    #[arg(short, long)]
    pub group: String,
    /// The comma-separated hex-encoded public keys of the signers to use.
    #[arg(short = 'S', long, value_delimiter = ',')]
    pub signers: Vec<String>,
}

impl Command {
    pub(crate) async fn run(self) -> Result<(), anyhow::Error> {
        let mut buf = vec![];
        stdin().read_to_end(&mut buf).await?;

        let pczt = Pczt::parse(&buf).map_err(|e| anyhow!("Failed to read PCZT: {:?}", e))?;

        let sighash = match pczt.clone().into_effects() {
            None => Err(anyhow!(
                "Not enough information to build the transaction's effects"
            ))?,
            Some(tx_data) => {
                let txid_parts = tx_data.digest(TxIdDigester);
                if matches!(tx_data.version(), TxVersion::V5)
                    && (tx_data.sapling_bundle().is_some() || tx_data.orchard_bundle().is_some())
                {
                    v5_signature_hash(&tx_data, &SignableInput::Shielded, &txid_parts)
                } else {
                    Err(anyhow!(
                        "Only version 5 transactions with shielded components are supported"
                    ))?
                }
            }
        };

        let signer = Signer::new(pczt.clone());

        let mut alphas = vec![];
        signer
            .sign_orchard_with(|_pczt, bundle, _| {
                alphas = bundle
                    .actions()
                    .iter()
                    .enumerate()
                    // TODO: remove unwrap
                    .filter_map(|(idx, a)| {
                        // TODO: improve dummy detection (check rk instead)
                        if a.spend().value().unwrap() != orchard::value::NoteValue::default() {
                            Some((idx, a.spend().alpha().unwrap()))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                Ok::<_, orchard::pczt::ParseError>(())
            })
            .unwrap();

        let mut signatures = vec![];

        let (pargs, args) = {
            let Command {
                config,
                server_url,
                group,
                signers,
            } = self;

            let config = frost_client::cli::config::Config::read(config)
                .map_err(|e| anyhow!(e.to_string()))?;

            let group = config
                .group
                .get(&group)
                .ok_or_else(|| anyhow!("Group not found"))?;

            let public_key_package =
                frost_client::reddsa::frost::redpallas::keys::PublicKeyPackage::deserialize(
                    &group.public_key_package,
                )?;

            let server_url = if let Some(server_url) = server_url {
                server_url
            } else {
                group
                    .server_url
                    .clone()
                    .ok_or_else(|| anyhow!("server-url required"))?
            };
            let server_url_parsed = url::Url::parse(&format!("https://{server_url}"))
                .map_err(|_| anyhow!("error parsing server-url"))?;

            let signers = signers
                .iter()
                .map(|s| {
                    let pubkey = PublicKey(hex::decode(s)?.to_vec());
                    let contact = group.participant_by_pubkey(&pubkey)?;
                    Ok((pubkey, contact.identifier()?))
                })
                .collect::<Result<HashMap<_, _>, Box<dyn std::error::Error>>>()
                .map_err(|e| anyhow!(e.to_string()))?;
            let num_signers = signers.len() as u16;

            let pargs = frost_client::coordinator::args::ProcessedArgs {
                num_signers,
                public_key_package,
                messages: vec![sighash.as_bytes().to_vec()],
                randomizers: alphas
                    .iter()
                    .map(|(_, alpha)| {
                        frost_client::reddsa::frost::redpallas::Randomizer::deserialize(
                            &alpha.to_repr(),
                        )
                        .map_err(|e| anyhow!(e.to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            };
            let args = frost_client::coordinator::comms::http::Args {
                signers,
                ip: server_url_parsed
                    .host_str()
                    .ok_or_else(|| anyhow!("host missing in URL"))?
                    .to_owned(),
                port: server_url_parsed
                    .port_or_known_default()
                    .expect("always works for https"),

                comm_privkey: Some(
                    config
                        .communication_key
                        .clone()
                        .ok_or_else(|| anyhow!("user not initialized"))?
                        .privkey
                        .clone(),
                ),
                comm_pubkey: Some(
                    config
                        .communication_key
                        .ok_or_else(|| anyhow!("user not initialized"))?
                        .pubkey
                        .clone(),
                ),
            };
            (pargs, args)
        };

        let mut comms = frost_client::coordinator::comms::http::HTTPComms::new(&pargs, &args)
            .map_err(|e| anyhow!(e.to_string()))?;
        let signature = frost_client::coordinator::cli::coordinator(&mut comms, pargs)
            .await
            .map_err(|e| anyhow!(e.to_string()))?;

        let signature: [u8; 64] = signature.serialize()?.try_into().unwrap();
        let signature = redpallas::Signature::<SpendAuth>::from(signature);
        signatures.push((alphas[0].0, signature));

        let signer = Signer::new(pczt.clone());
        let signer = signer
            .sign_orchard_with(|_pczt, bundle, _| {
                for (idx, signature) in signatures.into_iter() {
                    let action = &mut bundle.actions_mut()[idx];
                    action
                        .apply_signature(sighash.as_bytes().try_into().unwrap(), signature)
                        .unwrap();
                }
                Ok::<_, orchard::pczt::ParseError>(())
            })
            .map_err(|e| anyhow!("Error signing: {:?}", e))?;

        let pczt = signer.finish();

        stdout().write_all(&pczt.serialize()).await?;

        Ok(())
    }
}
