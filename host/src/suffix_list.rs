//! Public Suffix List used to validate that a request's rp.id is a registrable
//! suffix of the calling origin (the check the browser normally performs).
//!
//! Prefers the distro-managed list (`publicsuffix-list` package) and falls
//! back to the list embedded in the `psl` crate when none is installed.

use libwebauthn::ops::webauthn::psl::{PublicSuffixList, SystemPublicSuffixList};
use tracing::info;

pub fn load() -> Box<dyn PublicSuffixList> {
    match SystemPublicSuffixList::auto() {
        Ok(list) => {
            info!("using the system Public Suffix List");
            Box::new(list)
        }
        Err(err) => {
            info!(%err, "no system Public Suffix List; using the embedded copy");
            Box::new(EmbeddedPublicSuffixList)
        }
    }
}

pub struct EmbeddedPublicSuffixList;

impl PublicSuffixList for EmbeddedPublicSuffixList {
    fn public_suffix(&self, host: &str) -> Option<String> {
        ::psl::suffix_str(host).map(str::to_owned)
    }

    fn registrable_domain(&self, host: &str) -> Option<String> {
        ::psl::domain_str(host).map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_list_resolves_common_suffixes() {
        let psl = EmbeddedPublicSuffixList;
        assert_eq!(psl.public_suffix("example.com").as_deref(), Some("com"));
        assert_eq!(psl.public_suffix("bbc.co.uk").as_deref(), Some("co.uk"));
        assert_eq!(psl.registrable_domain("login.example.com").as_deref(), Some("example.com"));
        assert_eq!(psl.registrable_domain("accounts.google.com").as_deref(), Some("google.com"));
        assert_eq!(psl.registrable_domain("co.uk"), None);
    }
}
