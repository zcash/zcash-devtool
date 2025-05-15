use bech32::{primitives::decode::CheckedHrpstring, Bech32, Bech32m};
use phf::phf_map;
use regex::Regex;
use sha2::Digest;
use sha3::Keccak256;

pub(crate) fn detect(s: &str) -> Option<ForeignAddress> {
    // Remove leading and trailing whitespace, to handle copy-paste errors.
    let s = s.trim();

    // Try decoding as Bech32.
    if let Ok(parsed) = CheckedHrpstring::new::<Bech32>(s) {
        // If we reached this point, the encoding is found to be valid Bech32.
        if let Some(&token_class) = BECH32_HRP.get(parsed.hrp().as_str()) {
            return Some(ForeignAddress { token_class });
        }
    }

    // Try decoding as Bech32m.
    if let Ok(parsed) = CheckedHrpstring::new::<Bech32m>(s) {
        // If we reached this point, the encoding is found to be valid Bech32m.
        if let Some(&token_class) = BECH32M_HRP.get(parsed.hrp().as_str()) {
            return Some(ForeignAddress { token_class });
        }
    }

    // Try decoding as Base58Check.
    if let Ok(decoded) = bs58::decode(s).with_check(None).into_vec() {
        if !decoded.is_empty() {
            if let Some(&token_class) = B58CHECK_BITCOIN_PREFIX_1.get(&decoded[..1]) {
                return Some(ForeignAddress { token_class });
            }
        }
    };

    // Try decoding as Base58Check.
    if let Ok(decoded) = bs58::decode(s)
        .with_alphabet(bs58::Alphabet::RIPPLE)
        .with_check(None)
        .into_vec()
    {
        if !decoded.is_empty() {
            if let Some(&token_class) = B58CHECK_RIPPLE_PREFIX_1.get(&decoded[..1]) {
                return Some(ForeignAddress { token_class });
            }
        }
    };

    // Try decoding as an Ethereum address.
    if Regex::new(r"^0x[0-9a-fA-F]{40}$")
        .expect("valid")
        .is_match(s)
    {
        // If it's all lowercase or all uppercase then this is all we can validate.
        if Regex::new(r"^0x[0-9a-f]{40}$").expect("valid").is_match(s)
            || Regex::new(r"^0x[0-9A-F]{40}$").expect("valid").is_match(s)
        {
            return Some(ForeignAddress {
                token_class: TokenClass::EvmFork,
            });
        }

        // Otherwise try decoding as an ERC-55 address.
        let hex_chars = &s[2..];
        let hashed_address = hex::encode(Keccak256::digest(hex_chars.to_ascii_lowercase()));
        if hex_chars.chars().enumerate().all(|(i, c)| {
            c.is_ascii_digit()
                || (u8::from_str_radix(&hashed_address[i..i + 1], 16).unwrap() >= 8)
                    == c.is_ascii_uppercase()
        }) {
            return Some(ForeignAddress {
                token_class: TokenClass::EvmFork,
            });
        }
    }

    // If we reach here, we didn't detect anything.
    None
}

pub(crate) fn inspect(addr: ForeignAddress) {
    eprintln!("Not a Zcash address");
    eprintln!();
    eprintln!("Token class: {:?}", addr.token_class);
}

/// Information about a non-Zcash (foreign) address.
#[derive(Debug)]
pub(crate) struct ForeignAddress {
    token_class: TokenClass,
}

/// The class of token that can be sent to a given address.
#[derive(Clone, Copy, Debug)]
enum TokenClass {
    /// Bitcoin, and any forks of it that persist.
    Bitcoin,
    /// Testnet Bitcoin, as well as many many code forks that didn't change testnet
    /// prefixes.
    TestnetBitcoin,
    /// Regtest Bitcoin, not relevant outside Bitcoin Core codebase.
    RegtestBitcoin,

    /// Ethereum (which has a frustrating address format), or any of its many many chain
    /// or code forks (which did not alter it). The networks that can use these addresses
    /// [include]:
    ///
    /// - Ethereum
    /// - Polygon
    /// - BSC (BNB Chain)
    /// - Fantom
    /// - Avalanche (C-Chain)
    ///
    /// [include]: https://support.metamask.io/start/learn/the-ethereum-address-format-and-why-it-matters-when-using-metamask/
    EvmFork,

    /// Tokens on the XRP Ledger.
    XrpLedger,
}

/// A map from one-byte Base58Check prefixes decoded using the Bitcoin alphabet, to the
/// token class that the address can receive.
///
/// - https://en.bitcoin.it/wiki/List_of_address_prefixes
static B58CHECK_BITCOIN_PREFIX_1: phf::Map<[u8; 1], TokenClass> = phf_map! {
    [0x00] => TokenClass::Bitcoin,
    [0x05] => TokenClass::Bitcoin,
    [0x6f] => TokenClass::TestnetBitcoin,
    [0xc4] => TokenClass::TestnetBitcoin,
};

/// A map from one-byte Base58Check prefixes decoded using the Ripple alphabet, to the
/// token class that the address can receive.
///
/// - https://xrpl.org/docs/references/protocol/data-types/base58-encodings
static B58CHECK_RIPPLE_PREFIX_1: phf::Map<[u8; 1], TokenClass> = phf_map! {
    [0x00] => TokenClass::XrpLedger,
};

/// A map from Bech32 HRPs to the token class that the address can receive.
///
/// [SLIP-0173] has a big list of these, but they need to be individually mapped to token
/// classes.
///
/// [SLIP-0173]: https://github.com/satoshilabs/slips/blob/master/slip-0173.md
static BECH32_HRP: phf::Map<&'static str, TokenClass> = phf_map! {
    "bc" => TokenClass::Bitcoin,
    "bcrt" => TokenClass::RegtestBitcoin,
    "tb" => TokenClass::TestnetBitcoin,
};

/// A map from Bech32m HRPs to the token class that the address can receive.
///
/// [SLIP-0173] HRPs might happen to also be Bech32m HRPs (this is what Bitcoin did, and
/// thus anyone who forked their code), but this should be checked for each case.
///
/// [SLIP-0173]: https://github.com/satoshilabs/slips/blob/master/slip-0173.md
static BECH32M_HRP: phf::Map<&'static str, TokenClass> = phf_map! {
    "bc" => TokenClass::Bitcoin,
    "bcrt" => TokenClass::RegtestBitcoin,
    "tb" => TokenClass::TestnetBitcoin,
};
