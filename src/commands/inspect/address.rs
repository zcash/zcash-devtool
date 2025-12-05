use group::GroupEncoding;
use zcash_address::{
    unified::{self, Container, Encoding},
    ConversionError, ToAddress, ZcashAddress,
};
use zcash_protocol::consensus::NetworkType;

#[allow(dead_code)]
enum AddressKind {
    Sprout([u8; 64]),
    Sapling([u8; 43]),
    Unified(unified::Address),
    P2pkh([u8; 20]),
    P2sh([u8; 20]),
    Tex([u8; 20]),
}

struct Address {
    net: NetworkType,
    kind: AddressKind,
}

impl zcash_address::TryFromAddress for Address {
    type Error = ();

    fn try_from_sprout(
        net: NetworkType,
        data: [u8; 64],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Sprout(data),
        })
    }

    fn try_from_sapling(
        net: NetworkType,
        data: [u8; 43],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Sapling(data),
        })
    }

    fn try_from_unified(
        net: NetworkType,
        data: unified::Address,
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Unified(data),
        })
    }

    fn try_from_transparent_p2pkh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::P2pkh(data),
        })
    }

    fn try_from_transparent_p2sh(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::P2sh(data),
        })
    }

    fn try_from_tex(
        net: NetworkType,
        data: [u8; 20],
    ) -> Result<Self, ConversionError<Self::Error>> {
        Ok(Address {
            net,
            kind: AddressKind::Tex(data),
        })
    }
}

pub(crate) fn inspect(addr: ZcashAddress) {
    eprintln!("Zcash address");

    match addr.convert::<Address>() {
        // TODO: Check for valid internals once we have migrated to a newer zcash_address
        // version with custom errors.
        Err(_) => unreachable!(),
        Ok(addr) => {
            eprintln!(
                " - Network: {}",
                match addr.net {
                    NetworkType::Main => "main",
                    NetworkType::Test => "testnet",
                    NetworkType::Regtest => "regtest",
                }
            );
            eprintln!(
                " - Kind: {}",
                match addr.kind {
                    AddressKind::Sprout(_) => "Sprout",
                    AddressKind::Sapling(_) => "Sapling",
                    AddressKind::Unified(_) => "Unified Address",
                    AddressKind::P2pkh(_) => "Transparent P2PKH",
                    AddressKind::P2sh(_) => "Transparent P2SH",
                    AddressKind::Tex(_) => "TEX (ZIP 320)",
                }
            );

            match addr.kind {
                AddressKind::Sapling(bytes) => check_sapling_receiver(bytes, "  "),
                AddressKind::Unified(ua) => {
                    eprintln!(" - Receivers:");
                    for receiver in ua.items() {
                        match receiver {
                            unified::Receiver::Orchard(data) => {
                                eprintln!(
                                    "   - Orchard ({})",
                                    unified::Address::try_from_items(vec![
                                        unified::Receiver::Orchard(data)
                                    ])
                                    .unwrap()
                                    .encode(&addr.net)
                                );
                            }
                            unified::Receiver::Sapling(data) => {
                                eprintln!(
                                    "   - Sapling ({})",
                                    ZcashAddress::from_sapling(addr.net, data)
                                );
                                check_sapling_receiver(data, "    ");
                            }
                            unified::Receiver::P2pkh(data) => {
                                eprintln!(
                                    "   - Transparent P2PKH ({})",
                                    ZcashAddress::from_transparent_p2pkh(addr.net, data)
                                );
                            }
                            unified::Receiver::P2sh(data) => {
                                eprintln!(
                                    "   - Transparent P2SH ({})",
                                    ZcashAddress::from_transparent_p2sh(addr.net, data)
                                );
                            }
                            unified::Receiver::Unknown { typecode, data } => {
                                eprintln!("   - Unknown");
                                eprintln!("     - Typecode: {typecode}");
                                eprintln!("     - Payload: {}", hex::encode(data));
                            }
                        }
                    }
                }
                AddressKind::P2pkh(data) => {
                    eprintln!(
                        " - Corresponding TEX: {}",
                        ZcashAddress::from_tex(addr.net, data),
                    );
                }
                AddressKind::Tex(data) => {
                    eprintln!(
                        " - Corresponding P2PKH: {}",
                        ZcashAddress::from_transparent_p2pkh(addr.net, data),
                    );
                }
                _ => (),
            }
        }
    }
}

fn check_sapling_receiver(mut bytes: [u8; 43], indent: &str) {
    if sapling::PaymentAddress::from_bytes(&bytes).is_none() {
        let diversifier = sapling::Diversifier(bytes[..11].try_into().unwrap());
        if diversifier.g_d().is_none() {
            eprintln!(
                "{indent} WARNING: Invalid diversifier! {}",
                hex::encode(diversifier.0),
            );
        }

        let mut pk_d = bytes[11..].try_into().unwrap();
        if jubjub::SubgroupPoint::from_bytes(&pk_d).is_none().into() {
            eprintln!(
                "{indent} WARNING: Invalid pk_d encoding! {}",
                hex::encode(pk_d),
            );
            // Try reversing the pk_d bytes.
            pk_d.reverse();
            if jubjub::SubgroupPoint::from_bytes(&pk_d).is_some().into() {
                eprintln!("{indent} Byte-reversed pk_d is valid; check the address encoder.");
                return;
            }
        }

        // Try reversing all of the bytes.
        let mut reversed_bytes = bytes;
        reversed_bytes.reverse();
        if sapling::PaymentAddress::from_bytes(&reversed_bytes).is_some() {
            eprintln!("{indent} Parsing as `rev(bytes)` works; check the address encoder.");
            return;
        }

        // Try reversing `d` and `pk_d`.
        let mut swapped_bytes = [0; 43];
        swapped_bytes[..11].copy_from_slice(&bytes[32..]);
        swapped_bytes[11..].copy_from_slice(&bytes[..32]);
        if sapling::PaymentAddress::from_bytes(&swapped_bytes).is_some() {
            eprintln!("{indent} Parsing as `pk_d || d` works; check the address encoder.");
            return;
        } else {
            // Try reversing the diversifier bytes in the swapped encoding.
            swapped_bytes[..11].reverse();
            if sapling::PaymentAddress::from_bytes(&swapped_bytes).is_some() {
                eprintln!("{indent} Parsing as `pk_d || rev(d)` works; check the address encoder.");
                return;
            }
        }

        // Try reversing the diversifier bytes. Check this last because 50% of
        // diversifiers are valid, and this could be a false positive.
        bytes[..11].reverse();
        if sapling::PaymentAddress::from_bytes(&swapped_bytes).is_some() {
            eprintln!("{indent} Byte-reversed diversifier is valid; check the address encoder.");
        }
    }
}
