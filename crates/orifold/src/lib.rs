//! **orifold** — standalone permutation engine for typosquat variants.
//!
//! The engine favors a large predictive search space, but it still sorts and
//! truncates candidates by relevance so low-value combinatorics do not drown the
//! top results when `max` is bounded.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

const ALT_TLDS: &[&str] = &[
    "net", "org", "io", "co", "app", "dev", "info", "ai", "cloud", "xyz", "top", "vip", "shop",
    "store", "online", "site", "live", "pro", "biz", "world", "services", "support", "digital",
    "tech", "systems", "solutions", "group", "finance", "security", "email", "network", "global",
    "today", "company", "inc", "cc", "me", "us", "uk", "de", "fr", "nl", "be", "ch", "es", "it",
    "pl", "pt", "jp", "kr", "cn", "in", "ru", "br", "mx", "au", "ca", "sg", "hk", "tr", "za",
    "io", "ly", "tv", "fm", "gg", "sh", "ws",
];
const PREDICTIVE_COMBO_TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "app", "dev", "info", "ai", "cloud", "xyz", "top", "vip",
    "shop", "store", "online", "site", "live", "pro", "biz", "world", "services", "support",
    "digital", "tech", "systems", "solutions", "group", "finance", "security", "email", "network",
    "global", "today", "company", "inc", "cc", "me", "us", "uk", "de", "fr", "nl", "be", "ch",
    "es", "it", "pl", "pt", "jp", "kr", "cn", "in", "ru", "br", "mx", "au", "ca", "sg", "hk",
];
const ADD_TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "app", "dev", "ai", "cloud", "xyz", "online", "site", "shop",
    "store", "tech", "security", "finance", "services", "support", "digital",
];
const PREFIX_KEYWORDS: &[&str] = &[
    "secure", "login", "portal", "auth", "mail", "account", "verify", "update", "service", "my",
    "web", "admin", "billing", "checkout",
];
const SUFFIX_KEYWORDS: &[&str] = &[
    "secure", "login", "cloud", "id", "app", "auth", "verify", "portal", "account", "support",
    "online", "help", "service",
];
const ADDITION_CHARS: &str = "abcdefghijklmnopqrstuvwxyz0123456789";
const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u', 'y'];
const NUMERAL_GROUPS: &[&[&str]] = &[
    &["0", "zero"],
    &["1", "one", "first"],
    &["2", "two", "second"],
    &["3", "three", "third"],
    &["4", "four", "fourth", "for"],
    &["5", "five", "fifth"],
    &["6", "six", "sixth"],
    &["7", "seven", "seventh"],
    &["8", "eight", "eighth"],
    &["9", "nine", "ninth"],
];
const COMMON_MULTI_SUFFIXES: &[&str] = &[
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk",
    "ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in",
    "com.br", "com.mx", "com.tr", "com.pl", "com.sg", "com.ar", "com.co", "co.za", "co.il",
];
const COMMON_MISSPELLINGS: &[(&str, &[&str])] = &[
    ("access", &["acess"]),
    ("account", &["acount"]),
    ("amazon", &["amazom", "ammazon"]),
    ("apple", &["appel"]),
    ("cloudflare", &["cloudfare"]),
    ("example", &["exampel"]),
    ("github", &["gihub"]),
    ("google", &["gogle", "googel"]),
    ("microsoft", &["micorsoft", "microsof"]),
    ("paypal", &["paypai"]),
    ("security", &["secuirty"]),
    ("youtube", &["youtub"]),
];
const HOMOPHONES: &[(&str, &[&str])] = &[
    ("base", &["bass"]),
    ("buy", &["by", "bye"]),
    ("mail", &["male"]),
    ("sale", &["sail"]),
    ("site", &["sight"]),
];

/// One candidate hostname and its permutation class.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct PermutationLine {
    pub fqdn: String,
    pub kind: String,
}

#[derive(Debug, thiserror::Error)]
pub enum OrifoldError {
    #[error("invalid apex domain: {0}")]
    InvalidDomain(String),
}

struct Generator {
    apex: String,
    domain: String,
    tld: String,
    max: usize,
    candidates: HashMap<String, String>,
    family_counts: HashMap<String, usize>,
}

impl Generator {
    fn new(apex: String, domain: String, tld: String, max: usize) -> Self {
        Self {
            apex,
            domain,
            tld,
            max,
            candidates: HashMap::new(),
            family_counts: HashMap::new(),
        }
    }

    fn push(&mut self, raw_fqdn: String, kind: &str) {
        self.push_with_cap(raw_fqdn, kind, true);
    }

    /// Pousse un candidat en ignorant le cap par famille (utilise pour les passes
    /// critiques comme PermutationCrossTld sur TLD primaires : on veut couvrir
    /// chaque permutation, peu importe le cap).
    fn push_uncapped(&mut self, raw_fqdn: String, kind: &str) {
        self.push_with_cap(raw_fqdn, kind, false);
    }

    fn push_with_cap(&mut self, raw_fqdn: String, kind: &str, enforce_cap: bool) {
        let normalized = match normalize_candidate(&raw_fqdn) {
            Some(value) => value,
            None => return,
        };
        if let Some(previous_kind) = self.candidates.get(&normalized) {
            if kind_rank(kind) < kind_rank(previous_kind) {
                if previous_kind == kind {
                    return;
                }
                if enforce_cap && !self.can_use_family(kind) {
                    return;
                }
                let previous_kind = previous_kind.clone();
                self.decrement_family(&previous_kind);
                self.increment_family(kind);
                self.candidates.insert(normalized, kind.to_string());
            }
        } else {
            if enforce_cap && !self.can_use_family(kind) {
                return;
            }
            self.increment_family(kind);
            self.candidates.insert(normalized, kind.to_string());
        }
    }

    fn push_domain(&mut self, raw_domain: String, kind: &str) {
        self.push(format!("{raw_domain}.{}", self.tld), kind);
    }

    fn push_keyword_pair(&mut self, keyword: &str) {
        self.push_domain(format!("{keyword}-{}", self.domain), "Keyword");
        self.push_domain(format!("{}-{keyword}", self.domain), "Keyword");
    }

    fn can_use_family(&self, kind: &str) -> bool {
        self.family_count(kind) < family_cap(kind, self.max)
    }

    fn family_count(&self, kind: &str) -> usize {
        self.family_counts.get(kind).copied().unwrap_or(0)
    }

    fn increment_family(&mut self, kind: &str) {
        *self.family_counts.entry(kind.to_string()).or_insert(0) += 1;
    }

    fn decrement_family(&mut self, kind: &str) {
        if let Some(value) = self.family_counts.get_mut(kind) {
            *value = value.saturating_sub(1);
        }
    }

    fn generate(&mut self) {
        self.profile_stage("Original", |s| s.push(s.apex.clone(), "Original"));
        self.profile_stage("Bitsquatting", |s| s.generate_bitsquatting());
        self.profile_stage("Mapped", |s| s.generate_mapped());
        self.profile_stage("NumeralSwap", |s| s.generate_numeral_swap());
        self.profile_stage("CommonMisspelling", |s| s.generate_common_misspellings());
        self.profile_stage("Homophones", |s| s.generate_homophones());
        self.profile_stage("Replacement", |s| s.generate_replacement());
        self.profile_stage("Insertion", |s| s.generate_insertion());
        self.profile_stage("Transposition", |s| s.generate_transposition());
        self.profile_stage("Omission", |s| s.generate_omission());
        self.profile_stage("Hyphenation", |s| s.generate_hyphenation());
        self.profile_stage("Repetition", |s| s.generate_repetition());
        self.profile_stage("StripDash", |s| s.generate_strip_dash());
        self.profile_stage("Subdomain", |s| s.generate_subdomain());
        self.profile_stage("MissingDot", |s| s.generate_missing_dot());
        self.profile_stage("ChangeDotDash", |s| s.generate_change_dot_dash());
        self.profile_stage("Tld", |s| s.generate_tld());
        self.profile_stage("AddTld", |s| s.generate_add_tld());
        self.profile_stage("FauxTld", |s| s.generate_faux_tld());
        self.profile_stage("WrongSld", |s| s.generate_wrong_sld());
        self.profile_stage("Keyword", |s| s.generate_keyword());
        self.profile_stage("MultiOmission", |s| s.generate_multi_omission());
        self.profile_stage("CountryCodeAffix", |s| s.generate_country_code_affix());
        self.profile_stage("ReverseWord", |s| s.generate_reverse_word());
        self.profile_stage("VowelSwap", |s| s.generate_vowel_swap());
        self.profile_stage("VowelShuffle", |s| s.generate_vowel_shuffle());
        self.profile_stage("DoubleVowelInsertion", |s| s.generate_double_vowel_insertion());
        self.profile_stage("SingularPluralize", |s| s.generate_singular_pluralize());
        self.profile_stage("Addition", |s| s.generate_addition());
        self.profile_stage("Homoglyph", |s| s.generate_homoglyphs());
        self.profile_stage("PermutationCrossTld", |s| s.generate_permutation_cross_tld());
        if self.max >= 1500 {
            self.profile_stage("PredictiveCombos", |s| s.generate_predictive_combos());
        }
        if self.max >= 2000 && self.candidates.len() < self.max {
            let chars = chars(&self.domain);
            self.profile_stage("DeepHomoglyph", |s| s.generate_deep_homoglyphs(&chars));
        }
    }

    fn profile_stage(&mut self, label: &str, stage: impl FnOnce(&mut Self)) {
        if std::env::var_os("ORIFOLD_PROFILE").is_some() {
            let before = self.candidates.len();
            let started = Instant::now();
            stage(self);
            eprintln!(
                "[orifold-profile] stage={} added={} total={} elapsed_ms={}",
                label,
                self.candidates.len().saturating_sub(before),
                self.candidates.len(),
                started.elapsed().as_millis()
            );
        } else {
            stage(self);
        }
    }

    fn finish(self) -> Vec<PermutationLine> {
        let original_domain = self.domain.clone();
        let original_tld = self.tld.clone();
        let mut ranked = self
            .candidates
            .into_iter()
            .map(|(fqdn, kind)| {
                let distance = candidate_distance(&original_domain, &fqdn);
                let tld_rank = tld_priority(&original_tld, &fqdn);
                let kind_rank = kind_rank(&kind);
                let len = fqdn.len();
                (kind_rank, distance, tld_rank, len, fqdn, kind)
            })
            .collect::<Vec<_>>();

        ranked.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.cmp(&right.1))
                .then(left.2.cmp(&right.2))
                .then(left.3.cmp(&right.3))
                .then(left.4.cmp(&right.4))
        });
        ranked.truncate(self.max.max(1));
        ranked
            .into_iter()
            .map(|(_, _, _, _, fqdn, kind)| PermutationLine { fqdn, kind })
            .collect()
    }

    fn generate_omission(&mut self) {
        let chars = chars(&self.domain);
        if chars.len() <= 2 {
            return;
        }
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            let mut candidate = chars.clone();
            candidate.remove(idx);
            self.push_domain(chars_to_string(&candidate), "Omission");
        }
    }

    fn generate_transposition(&mut self) {
        let chars = chars(&self.domain);
        if chars.len() <= 1 {
            return;
        }
        for idx in 0..chars.len() - 1 {
            if !is_mutable_domain_char(chars[idx]) || !is_mutable_domain_char(chars[idx + 1]) {
                continue;
            }
            let mut candidate = chars.clone();
            candidate.swap(idx, idx + 1);
            self.push_domain(chars_to_string(&candidate), "Transposition");
        }
    }

    fn generate_hyphenation(&mut self) {
        let chars = chars(&self.domain);
        if chars.len() <= 2 {
            return;
        }
        for idx in 1..chars.len() {
            if chars[idx - 1] == '.' || chars[idx] == '.' {
                continue;
            }
            let mut candidate = chars.clone();
            candidate.insert(idx, '-');
            self.push_domain(chars_to_string(&candidate), "Hyphenation");
        }
    }

    fn generate_repetition(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            let mut candidate = chars.clone();
            candidate.insert(idx + 1, chars[idx]);
            self.push_domain(chars_to_string(&candidate), "Repetition");
        }
    }

    fn generate_addition(&mut self) {
        if self.candidates.len() >= self.max {
            return;
        }
        let chars = chars(&self.domain);
        'outer: for idx in 0..=chars.len() {
            for ch in ADDITION_CHARS.chars() {
                let mut candidate = chars.clone();
                candidate.insert(idx, ch);
                self.push_domain(chars_to_string(&candidate), "Addition");
                if self.candidates.len() >= self.max {
                    break 'outer;
                }
            }
        }
    }

    fn generate_predictive_combos(&mut self) {
        if self.candidates.len() >= self.max {
            return;
        }
        let mut seeds = self
            .candidates
            .iter()
            .filter_map(|(fqdn, kind)| {
                if fqdn == &self.apex {
                    return None;
                }
                let (domain, tld) = split_domain_suffix(fqdn)?;
                if tld != self.tld {
                    return None;
                }
                Some((domain, kind.clone(), candidate_distance(&self.domain, fqdn)))
            })
            .collect::<Vec<_>>();

        seeds.sort_by(|left, right| {
            kind_rank(&left.1)
                .cmp(&kind_rank(&right.1))
                .then(left.2.cmp(&right.2))
                .then(left.0.len().cmp(&right.0.len()))
                .then(left.0.cmp(&right.0))
        });

        'seed_loop: for (domain, _, _) in seeds.into_iter().take(96) {
            for combo_tld in PREDICTIVE_COMBO_TLDS {
                if *combo_tld != self.tld {
                    self.push(format!("{}.{}", domain, combo_tld), "ComboTld");
                }
                self.push(format!("{}.{}.{}", domain, self.tld, combo_tld), "ComboAddTld");
                if self.candidates.len() >= self.max {
                    break 'seed_loop;
                }
            }
        }
    }

    fn generate_bitsquatting(&mut self) {
        let masks = [1_u8, 2, 4, 8, 16];
        let mut bytes = self.domain.as_bytes().to_vec();
        for idx in 0..bytes.len() {
            let original = bytes[idx];
            if !is_ascii_mutable_byte(original) {
                continue;
            }
            for mask in masks {
                let flipped = original ^ mask;
                if flipped == original || !is_ascii_mutable_byte(flipped) {
                    continue;
                }
                bytes[idx] = flipped;
                if let Ok(candidate) = String::from_utf8(bytes.clone()) {
                    self.push_domain(candidate, "Bitsquatting");
                }
            }
            bytes[idx] = original;
        }
    }

    fn generate_replacement(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            for replacement in keyboard_neighbors(chars[idx]).chars() {
                if replacement == chars[idx] {
                    continue;
                }
                let mut candidate = chars.clone();
                candidate[idx] = replacement;
                self.push_domain(chars_to_string(&candidate), "Replacement");
            }
        }
    }

    fn generate_insertion(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            for insert_char in keyboard_neighbors(chars[idx]).chars() {
                let mut left = chars.clone();
                left.insert(idx, insert_char);
                self.push_domain(chars_to_string(&left), "Insertion");

                let mut right = chars.clone();
                right.insert(idx + 1, insert_char);
                self.push_domain(chars_to_string(&right), "Insertion");
            }
        }
    }

    fn generate_subdomain(&mut self) {
        let chars = chars(&self.domain);
        if chars.len() <= 2 {
            return;
        }
        for idx in 1..chars.len() {
            if chars[idx - 1] == '.' || chars[idx] == '.' {
                continue;
            }
            let mut candidate = chars.clone();
            candidate.insert(idx, '.');
            self.push_domain(chars_to_string(&candidate), "Subdomain");
        }
    }

    fn generate_missing_dot(&mut self) {
        if !self.domain.contains('.') {
            return;
        }
        self.push_domain(self.domain.replace('.', ""), "MissingDot");
    }

    fn generate_change_dot_dash(&mut self) {
        if !self.domain.contains('.') {
            return;
        }
        self.push_domain(self.domain.replace('.', "-"), "ChangeDotDash");
    }

    fn generate_strip_dash(&mut self) {
        if !self.domain.contains('-') {
            return;
        }
        self.push_domain(self.domain.replace('-', ""), "StripDash");
    }

    fn generate_tld(&mut self) {
        if self.tld.contains('.') {
            return;
        }
        for alt_tld in ALT_TLDS {
            if *alt_tld != self.tld {
                self.push(format!("{}.{}", self.domain, alt_tld), "Tld");
            }
        }
    }

    fn generate_add_tld(&mut self) {
        if self.tld.contains('.') {
            return;
        }
        for alt_tld in ADD_TLDS {
            self.push(format!("{}.{}.{}", self.domain, self.tld, alt_tld), "AddTld");
        }
    }

    fn generate_faux_tld(&mut self) {
        if self.tld.contains('.') {
            return;
        }
        let mut chars = self.tld.chars();
        if let Some(first) = chars.next() {
            let rest: String = chars.collect();
            if !rest.is_empty() {
                self.push(format!("{}{}.{rest}", self.domain, first), "FauxTld");
            }
        }
    }

    fn generate_wrong_sld(&mut self) {
        for candidate_suffix in suffix_family_for(&self.tld) {
            if *candidate_suffix != self.tld {
                self.push(format!("{}.{}", self.domain, candidate_suffix), "WrongSld");
            }
        }
    }

    fn generate_keyword(&mut self) {
        for keyword in PREFIX_KEYWORDS {
            self.push_keyword_pair(keyword);
        }
        for keyword in SUFFIX_KEYWORDS {
            self.push_keyword_pair(keyword);
        }
    }

    /// Omission de 2 lettres consecutives ou non. Couvre : delivro (deliveroo - "eo").
    /// Limite : on ne genere que des paires plausibles pour eviter l'explosion combinatoire.
    fn generate_multi_omission(&mut self) {
        let chars = chars(&self.domain);
        if chars.len() <= 4 {
            return;
        }
        for first in 0..chars.len() {
            if !is_mutable_domain_char(chars[first]) {
                continue;
            }
            for second in first + 1..chars.len() {
                if !is_mutable_domain_char(chars[second]) {
                    continue;
                }
                let mut candidate = chars.clone();
                candidate.remove(second);
                candidate.remove(first);
                if candidate.len() < 2 {
                    continue;
                }
                self.push_domain(chars_to_string(&candidate), "MultiOmission");
            }
        }
    }

    /// Variantes "marque + code pays ISO 2 lettres" en prefixe/suffixe.
    /// La liste est figee (codes ISO 3166-1 alpha-2 des pays les plus actifs en typosquat).
    /// Couvre : rickowensfr.fr, brand-uk.com, debrand.de...
    /// Note : on garde uniquement les codes 2 lettres (pas les noms complets comme "france")
    /// pour eviter le piege des keywords arbitraires.
    fn generate_country_code_affix(&mut self) {
        // Codes ISO 3166-1 alpha-2 des pays les plus cibles par les typosquatters
        // (sources : rapports Group-IB, CSC, etc.). Liste fermee, figee, neutre.
        const ISO_COUNTRY_CODES: &[&str] = &[
            "fr", "us", "uk", "de", "es", "it", "be", "ch", "nl", "ca", "au", "jp", "kr", "br",
            "mx", "in", "ru", "tr", "pl", "pt", "se", "no", "dk", "fi", "ie", "nz", "za", "sg",
            "hk", "ar", "co", "cl", "il", "gr", "cz", "hu", "ro", "at",
        ];
        for code in ISO_COUNTRY_CODES {
            if *code == self.domain {
                continue;
            }
            // Forme suffixe accolee : rickowensfr
            self.push_domain(format!("{}{code}", self.domain), "CountryCodeAffix");
            // Forme suffixe avec tiret : brand-fr
            self.push_domain(format!("{}-{code}", self.domain), "CountryCodeAffix");
            // Forme prefixe accolee : frbrand (rare mais existe)
            self.push_domain(format!("{code}{}", self.domain), "CountryCodeAffix");
            // Forme prefixe avec tiret : fr-brand
            self.push_domain(format!("{code}-{}", self.domain), "CountryCodeAffix");
        }
    }

    /// Inversion de mots dans un domaine compose (separe par '-').
    /// Couvre : sncf-voyageurs -> voyageurs-sncf, voyagessncf, voyages-sncf, voyagesncf
    fn generate_reverse_word(&mut self) {
        if !self.domain.contains('-') {
            return;
        }
        let parts: Vec<String> = self
            .domain
            .split('-')
            .filter(|p| !p.is_empty())
            .map(|s| s.to_string())
            .collect();
        if parts.len() < 2 {
            return;
        }
        let reversed: Vec<String> = parts.iter().rev().cloned().collect();
        self.push_domain(reversed.join("-"), "ReverseWord");
        self.push_domain(reversed.join(""), "ReverseWord");
        self.push_domain(parts.join(""), "ReverseWord");
        if parts.len() >= 3 {
            for i in 0..parts.len() {
                let mut rotated = parts.clone();
                let first = rotated.remove(i);
                rotated.push(first);
                self.push_domain(rotated.join("-"), "ReverseWord");
                self.push_domain(rotated.join(""), "ReverseWord");
            }
        }
        // troncature singuliere de chaque mot (voyageurs -> voyages)
        for (idx, part) in parts.iter().enumerate() {
            if part.ends_with('s') && part.len() > 3 {
                let mut alt: Vec<String> = parts.clone();
                alt[idx] = part[..part.len() - 1].to_string();
                self.push_domain(alt.join("-"), "ReverseWord");
                self.push_domain(alt.join(""), "ReverseWord");
                let mut alt_rev = alt.clone();
                alt_rev.reverse();
                self.push_domain(alt_rev.join("-"), "ReverseWord");
                self.push_domain(alt_rev.join(""), "ReverseWord");
            }
        }
    }

    /// Applique les permutations principales (Omission, Transposition, Addition, Insertion,
    /// Replacement, Repetition, VowelSwap, Bitsquatting, Homoglyph) sur les TLD pertinents.
    /// C'est CRITIQUE : un typosquat comme snaptchat.fr (pour snapchat.com) doit etre detecte.
    ///
    /// Strategie en 2 passes :
    /// 1. Pour chaque seed (label permute), on republie d'abord sur les TLD PRIMAIRES
    ///    (com, fr, net, org, eu, io, co) afin que CHAQUE permutation soit couverte sur les
    ///    TLD les plus abuses, peu importe son rang.
    /// 2. Si capacite restante, on etend avec les TLD secondaires.
    fn generate_permutation_cross_tld(&mut self) {
        if self.tld.contains('.') {
            return;
        }
        // 4 TLD critiques garantis pour CHAQUE seed (pas de cap qui les coupe)
        let critical_tlds: &[&str] = &["com", "fr", "net", "eu"];
        // Extension primaire (cap-limite mais prioritaire)
        let primary_tlds: &[&str] = &["org", "io", "co", "us", "de", "uk"];
        let secondary_tlds: &[&str] = &[
            "es", "it", "be", "ch", "nl", "ca", "au", "info", "biz", "shop", "store", "online",
            "site", "app", "xyz", "top", "icu",
        ];

        let mut seeds: Vec<(String, usize)> = self
            .candidates
            .iter()
            .filter_map(|(fqdn, kind)| {
                if fqdn == &self.apex {
                    return None;
                }
                if !matches!(
                    kind.as_str(),
                    "Omission"
                        | "Transposition"
                        | "Addition"
                        | "Insertion"
                        | "Replacement"
                        | "Repetition"
                        | "VowelSwap"
                        | "Bitsquatting"
                        | "Homoglyph"
                        | "Mapped"
                        | "CommonMisspelling"
                        | "DoubleVowelInsertion"
                        | "Hyphenation"
                        | "MultiOmission"
                        | "CountryCodeAffix"
                ) {
                    return None;
                }
                let (domain, tld) = split_domain_suffix(fqdn)?;
                if tld != self.tld {
                    return None;
                }
                let rank = kind_rank(kind);
                Some((domain, rank))
            })
            .collect();

        seeds.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then_with(|| a.0.len().cmp(&b.0.len()))
                .then_with(|| a.0.cmp(&b.0))
        });

        // Passe 1 : TLD critiques pour TOUS les seeds (sans cap par famille)
        // Garantit que chaque permutation est couverte sur com/fr/net/eu
        // C'est ESSENTIEL : un typosquat comme snaptchat.fr doit etre detecte.
        for (domain, _) in seeds.iter() {
            for cross_tld in critical_tlds {
                if *cross_tld == self.tld {
                    continue;
                }
                self.push_uncapped(
                    format!("{}.{}", domain, cross_tld),
                    "PermutationCrossTld",
                );
                if self.candidates.len() >= self.max {
                    return;
                }
            }
        }

        let cap = family_cap("PermutationCrossTld", self.max);
        let mut produced = self
            .family_count("PermutationCrossTld");

        // Passe 2 : TLD primaires
        'pass2: for (domain, _) in seeds.iter() {
            for cross_tld in primary_tlds {
                if *cross_tld == self.tld {
                    continue;
                }
                self.push(format!("{}.{}", domain, cross_tld), "PermutationCrossTld");
                produced += 1;
                if produced >= cap || self.candidates.len() >= self.max {
                    break 'pass2;
                }
            }
        }

        // Passe 3 : TLD secondaires
        'pass3: for (domain, _) in seeds.iter() {
            for cross_tld in secondary_tlds {
                if *cross_tld == self.tld {
                    continue;
                }
                self.push(format!("{}.{}", domain, cross_tld), "PermutationCrossTld");
                produced += 1;
                if produced >= cap || self.candidates.len() >= self.max {
                    break 'pass3;
                }
            }
        }
    }

    fn generate_vowel_swap(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            let original = chars[idx];
            if !VOWELS.contains(&original) {
                continue;
            }
            for replacement in VOWELS {
                if *replacement == original {
                    continue;
                }
                let mut candidate = chars.clone();
                candidate[idx] = *replacement;
                self.push_domain(chars_to_string(&candidate), "VowelSwap");
            }
        }
    }

    fn generate_vowel_shuffle(&mut self) {
        let chars = chars(&self.domain);
        let vowel_positions = chars
            .iter()
            .enumerate()
            .filter_map(|(idx, ch)| if VOWELS.contains(ch) { Some(idx) } else { None })
            .collect::<Vec<_>>();
        if vowel_positions.len() < 2 {
            return;
        }
        let original_vowels = vowel_positions.iter().map(|idx| chars[*idx]).collect::<Vec<_>>();
        let mut unique = HashSet::new();
        let mut working = original_vowels.clone();
        permute_vowels(&mut working, 0, &mut |candidate_vowels| {
            if candidate_vowels == original_vowels {
                return;
            }
            if unique.insert(candidate_vowels.clone()) {
                let mut candidate = chars.clone();
                for (position, vowel) in vowel_positions.iter().zip(candidate_vowels.iter()) {
                    candidate[*position] = *vowel;
                }
                self.push_domain(chars_to_string(&candidate), "VowelShuffle");
            }
        });
    }

    fn generate_double_vowel_insertion(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !VOWELS.contains(&chars[idx]) {
                continue;
            }
            for vowel in VOWELS {
                let mut candidate = chars.clone();
                candidate.insert(idx + 1, *vowel);
                self.push_domain(chars_to_string(&candidate), "DoubleVowelInsertion");
            }
        }
    }

    fn generate_numeral_swap(&mut self) {
        for group in NUMERAL_GROUPS {
            for source in *group {
                if !self.domain.contains(source) {
                    continue;
                }
                for target in *group {
                    if source == target {
                        continue;
                    }
                    self.push_domain(self.domain.replace(source, target), "NumeralSwap");
                }
            }
        }
    }

    fn generate_singular_pluralize(&mut self) {
        if self.domain.ends_with('s') && self.domain.len() > 2 {
            self.push_domain(self.domain.trim_end_matches('s').to_string(), "SingularPluralize");
        } else if self.domain.ends_with('y') && self.domain.len() > 2 {
            self.push_domain(format!("{}ies", &self.domain[..self.domain.len() - 1]), "SingularPluralize");
        } else {
            self.push_domain(format!("{}s", self.domain), "SingularPluralize");
        }
    }

    fn generate_common_misspellings(&mut self) {
        for (correct, misspellings) in COMMON_MISSPELLINGS {
            if self.domain == *correct {
                for misspelling in *misspellings {
                    self.push_domain((*misspelling).to_string(), "CommonMisspelling");
                }
            }
        }
    }

    fn generate_homophones(&mut self) {
        for (base, values) in HOMOPHONES {
            if self.domain == *base {
                for value in *values {
                    self.push_domain((*value).to_string(), "Homophones");
                }
            }
        }
    }

    fn generate_mapped(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            for replacement in mapped_replacements(chars[idx]) {
                let mut candidate = chars.clone();
                candidate.splice(idx..=idx, replacement.chars());
                self.push_domain(chars_to_string(&candidate), "Mapped");
            }
        }
    }

    fn generate_homoglyphs(&mut self) {
        let chars = chars(&self.domain);
        for idx in 0..chars.len() {
            if !is_mutable_domain_char(chars[idx]) {
                continue;
            }
            for replacement in homoglyph_replacements(chars[idx]) {
                self.push_domain(apply_replacements(&chars, &[(idx, replacement)]), "Homoglyph");
            }
        }
    }

    fn generate_deep_homoglyphs(&mut self, chars: &[char]) {
        let mutable_positions = chars
            .iter()
            .enumerate()
            .filter_map(|(idx, ch)| if is_mutable_domain_char(*ch) { Some(idx) } else { None })
            .collect::<Vec<_>>();

        for left_idx in 0..mutable_positions.len() {
            let left_pos = mutable_positions[left_idx];
            let left_replacements = homoglyph_replacements(chars[left_pos]);
            if left_replacements.is_empty() {
                continue;
            }
            for right_idx in left_idx + 1..mutable_positions.len() {
                let right_pos = mutable_positions[right_idx];
                let right_replacements = homoglyph_replacements(chars[right_pos]);
                if right_replacements.is_empty() {
                    continue;
                }
                for left_replacement in left_replacements {
                    for right_replacement in right_replacements {
                        self.push_domain(
                            apply_replacements(
                                chars,
                                &[(left_pos, left_replacement), (right_pos, right_replacement)],
                            ),
                            "Homoglyph",
                        );
                    }
                }
            }
        }
    }
}

fn chars(value: &str) -> Vec<char> {
    value.chars().collect()
}

fn chars_to_string(chars: &[char]) -> String {
    chars.iter().collect()
}

fn is_ascii_mutable_byte(byte: u8) -> bool {
    matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-')
}

fn is_mutable_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '-' || ch == '.'
}

fn keyboard_neighbors(ch: char) -> &'static str {
    match ch {
        'a' => "qwsz",
        'b' => "vghn",
        'c' => "xdfv",
        'd' => "serfcx",
        'e' => "wsdr",
        'f' => "drtgvc",
        'g' => "ftyhbv",
        'h' => "gyujnb",
        'i' => "ujko",
        'j' => "huikmn",
        'k' => "jiolm",
        'l' => "kop",
        'm' => "njk",
        'n' => "bhjm",
        'o' => "iklp",
        'p' => "ol",
        'q' => "wa",
        'r' => "edft",
        's' => "awedxz",
        't' => "rfgy",
        'u' => "yhji",
        'v' => "cfgb",
        'w' => "qase",
        'x' => "zsdc",
        'y' => "tghu",
        'z' => "asx",
        '0' => "9op",
        '1' => "2q",
        '2' => "13w",
        '3' => "24e",
        '4' => "35r",
        '5' => "46t",
        '6' => "57y",
        '7' => "68u",
        '8' => "79i",
        '9' => "80o",
        _ => "",
    }
}

fn mapped_replacements(ch: char) -> &'static [&'static str] {
    match ch {
        'a' => &["4"],
        'b' => &["8"],
        'e' => &["3"],
        'g' => &["9"],
        'i' => &["1"],
        'l' => &["1"],
        'o' => &["0"],
        's' => &["5"],
        't' => &["7"],
        'z' => &["2"],
        _ => &[],
    }
}

fn homoglyph_replacements(ch: char) -> &'static [&'static str] {
    match ch {
        '0' => &["o"],
        '1' => &["l", "i", "ı"],
        '2' => &["ƻ"],
        '5' => &["ƽ"],
        'a' => &["à", "á", "â", "ã", "ä", "å", "ɑ", "ạ", "ǎ", "ă", "ȧ", "ą", "ə"],
        'b' => &["d", "ʙ", "ɓ", "ḃ", "ḅ", "ḇ", "ƅ"],
        'c' => &["e", "ƈ", "ċ", "ć", "ç", "č", "ĉ", "ᴄ"],
        'd' => &["b", "cl", "ɗ", "đ", "ď", "ɖ", "ḑ", "ḋ", "ḍ", "ḏ", "ḓ"],
        'e' => &["c", "é", "è", "ê", "ë", "ē", "ĕ", "ě", "ė", "ẹ", "ę", "ȩ", "ɇ", "ḛ"],
        'f' => &["ƒ", "ḟ"],
        'g' => &["q", "ɢ", "ɡ", "ġ", "ğ", "ǵ", "ģ", "ĝ", "ǧ", "ǥ"],
        'h' => &["ĥ", "ȟ", "ħ", "ɦ", "ḧ", "ḩ", "ⱨ", "ḣ", "ḥ", "ḫ", "ẖ"],
        'i' => &["l", "í", "ì", "ï", "ı", "ɩ", "ǐ", "ĭ", "ỉ", "ị", "ɨ", "ȋ", "ī", "ɪ"],
        'j' => &["ʝ", "ǰ", "ɉ", "ĵ"],
        'k' => &["lc", "ḳ", "ḵ", "ⱪ", "ķ", "ᴋ"],
        'l' => &["i", "ɫ", "ł", "ı", "ɩ"],
        'm' => &["n", "nn", "rn", "rr", "ṁ", "ṃ", "ᴍ", "ɱ", "ḿ"],
        'n' => &["m", "r", "ń", "ṅ", "ṇ", "ṉ", "ñ", "ņ", "ǹ", "ň", "ꞑ"],
        'o' => &["0", "ȯ", "ọ", "ỏ", "ơ", "ó", "ö", "ᴏ"],
        'p' => &["ƿ", "ƥ", "ṕ", "ṗ"],
        'q' => &["g", "ʠ"],
        'r' => &["ʀ", "ɼ", "ɽ", "ŕ", "ŗ", "ř", "ɍ", "ɾ", "ȓ", "ȑ", "ṙ", "ṛ", "ṟ"],
        's' => &["ʂ", "ś", "ṣ", "ṡ", "ș", "ŝ", "š", "ꜱ"],
        't' => &["ţ", "ŧ", "ṫ", "ṭ", "ț", "ƫ"],
        'u' => &["ᴜ", "ǔ", "ŭ", "ü", "ʉ", "ù", "ú", "û", "ũ", "ū", "ų", "ư", "ů", "ű", "ȕ", "ȗ", "ụ"],
        'v' => &["ṿ", "ⱱ", "ᶌ", "ṽ", "ⱴ", "ᴠ"],
        'w' => &["vv", "ŵ", "ẁ", "ẃ", "ẅ", "ⱳ", "ẇ", "ẉ", "ẘ", "ᴡ"],
        'x' => &["ẋ", "ẍ"],
        'y' => &["ʏ", "ý", "ÿ", "ŷ", "ƴ", "ȳ", "ɏ", "ỿ", "ẏ", "ỵ"],
        'z' => &["ʐ", "ż", "ź", "ᴢ", "ƶ", "ẓ", "ẕ", "ⱬ"],
        _ => &[],
    }
}

fn kind_rank(kind: &str) -> usize {
    match kind {
        "Original" => 0,
        "CommonMisspelling" | "Mapped" | "NumeralSwap" | "Homophones" | "Bitsquatting"
        | "Replacement" | "Transposition" | "Omission" | "WrongSld" | "Repetition" | "Homoglyph"
        | "Keyword" | "MultiOmission" | "ReverseWord" | "CountryCodeAffix" => 1,
        "Insertion" | "Hyphenation" | "Subdomain" | "Tld" | "VowelSwap"
        | "SingularPluralize" | "PermutationCrossTld" => 2,
        "VowelShuffle" | "DoubleVowelInsertion" | "Addition" | "AddTld" | "ChangeDotDash"
        | "MissingDot" | "StripDash" | "FauxTld" => 3,
        "ComboTld" | "ComboAddTld" => 4,
        _ => 5,
    }
}

fn scaled_cap(max: usize, numerator: usize, denominator: usize, min_cap: usize, max_cap: usize) -> usize {
    let ratio_cap = (max.saturating_mul(numerator) / denominator).max(min_cap);
    ratio_cap.min(max_cap)
}

fn family_cap(kind: &str, max: usize) -> usize {
    match kind {
        "Original" => 1,
        "CommonMisspelling" => scaled_cap(max, 1, 10, 8, 120),
        "Homophones" => scaled_cap(max, 1, 12, 4, 80),
        "NumeralSwap" => scaled_cap(max, 1, 10, 16, 120),
        "Mapped" => scaled_cap(max, 1, 10, 24, 140),
        "Bitsquatting" => scaled_cap(max, 1, 8, 32, 220),
        "Replacement" => scaled_cap(max, 1, 6, 48, 280),
        "Insertion" => scaled_cap(max, 1, 6, 48, 280),
        "Transposition" => scaled_cap(max, 1, 8, 24, 160),
        "Omission" => scaled_cap(max, 1, 8, 24, 160),
        "Repetition" => scaled_cap(max, 1, 8, 24, 180),
        "WrongSld" => scaled_cap(max, 1, 10, 12, 100),
        "Keyword" => scaled_cap(max, 1, 6, 24, 160),
        "MultiOmission" => scaled_cap(max, 1, 6, 64, 320),
        "CountryCodeAffix" => scaled_cap(max, 1, 6, 64, 320),
        "ReverseWord" => scaled_cap(max, 1, 12, 8, 60),
        "PermutationCrossTld" => scaled_cap(max, 2, 3, 800, 6000),
        "Homoglyph" => scaled_cap(max, 1, 8, 80, 320),
        "Hyphenation" => scaled_cap(max, 1, 10, 16, 120),
        "Subdomain" => scaled_cap(max, 1, 12, 12, 100),
        "Tld" => scaled_cap(max, 1, 4, 40, 260),
        "AddTld" => scaled_cap(max, 1, 3, 60, 360),
        "VowelSwap" => scaled_cap(max, 1, 10, 16, 140),
        "SingularPluralize" => 16,
        "VowelShuffle" => scaled_cap(max, 1, 12, 8, 90),
        "DoubleVowelInsertion" => scaled_cap(max, 1, 12, 8, 90),
        "Addition" => scaled_cap(max, 1, 3, 80, 420),
        "ChangeDotDash" => scaled_cap(max, 1, 12, 8, 80),
        "MissingDot" => scaled_cap(max, 1, 12, 4, 40),
        "StripDash" => scaled_cap(max, 1, 12, 4, 40),
        "FauxTld" => scaled_cap(max, 1, 16, 4, 40),
        "ComboTld" => if max >= 1500 { scaled_cap(max, 3, 5, 400, 3200) } else { 0 },
        "ComboAddTld" => if max >= 3000 { scaled_cap(max, 7, 20, 220, 2200) } else { 0 },
        _ => scaled_cap(max, 1, 8, 16, 120),
    }
}

fn normalize_candidate(raw: &str) -> Option<String> {
    let lowered = raw.trim().trim_end_matches('.').to_lowercase();
    if lowered.is_empty() {
        return None;
    }
    if lowered.is_ascii() {
        return if is_valid_fqdn(&lowered) {
            Some(lowered)
        } else {
            None
        };
    }
    let ascii = idna::domain_to_ascii(&lowered).ok()?;
    let normalized = ascii.trim().trim_end_matches('.').to_lowercase();
    if is_valid_fqdn(&normalized) {
        Some(normalized)
    } else {
        None
    }
}

fn is_valid_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

fn is_valid_fqdn(fqdn: &str) -> bool {
    if fqdn.len() > 253 || !fqdn.contains('.') {
        return false;
    }
    fqdn.split('.').all(is_valid_label)
}

fn split_apex(apex: &str) -> Result<(String, String), OrifoldError> {
    let normalized = normalize_candidate(apex).ok_or_else(|| OrifoldError::InvalidDomain(apex.to_string()))?;
    let (domain, tld) =
        split_domain_suffix(&normalized).ok_or_else(|| OrifoldError::InvalidDomain(apex.to_string()))?;
    if domain.is_empty() || tld.is_empty() {
        return Err(OrifoldError::InvalidDomain(apex.to_string()));
    }
    Ok((domain, tld))
}

fn split_domain_suffix(host: &str) -> Option<(String, String)> {
    for suffix in COMMON_MULTI_SUFFIXES {
        let suffix_with_dot = format!(".{suffix}");
        if host.ends_with(&suffix_with_dot) {
            let domain = host.strip_suffix(&suffix_with_dot)?.to_string();
            if !domain.is_empty() {
                return Some((domain, (*suffix).to_string()));
            }
        }
    }
    let (domain, suffix) = host.rsplit_once('.')?;
    Some((domain.to_string(), suffix.to_string()))
}

fn suffix_family_for(suffix: &str) -> &'static [&'static str] {
    match suffix {
        "ac.uk" | "co.uk" | "gov.uk" | "ltd.uk" | "me.uk" | "net.uk" | "org.uk" | "plc.uk" | "sch.uk" => {
            &["ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "sch.uk"]
        }
        "ac.jp" | "co.jp" | "go.jp" | "ne.jp" | "or.jp" => &["ac.jp", "co.jp", "go.jp", "ne.jp", "or.jp"],
        "com.au" | "net.au" | "org.au" | "edu.au" | "gov.au" | "asn.au" | "id.au" => {
            &["com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au"]
        }
        "co.nz" | "net.nz" | "org.nz" | "govt.nz" | "ac.nz" => &["co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz"],
        "co.in" | "firm.in" | "net.in" | "org.in" | "gen.in" | "ind.in" => {
            &["co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in"]
        }
        "com.br" => &["com.br", "net.br", "org.br", "gov.br"],
        "com.mx" => &["com.mx", "org.mx", "gob.mx", "edu.mx", "net.mx"],
        "com.tr" => &["com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr"],
        "com.pl" => &["com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl"],
        "com.sg" => &["com.sg", "net.sg", "org.sg", "gov.sg", "edu.sg"],
        "com.ar" => &["com.ar", "net.ar", "org.ar", "gov.ar", "edu.ar"],
        "com.co" => &["com.co", "net.co", "org.co", "gov.co", "edu.co"],
        "co.za" => &["co.za", "net.za", "org.za", "gov.za", "ac.za"],
        "co.il" => &["co.il", "org.il", "gov.il", "ac.il", "net.il"],
        _ => &[],
    }
}

fn candidate_distance(original_domain: &str, candidate_fqdn: &str) -> usize {
    let candidate_domain = split_domain_suffix(candidate_fqdn)
        .map(|(domain, _)| domain)
        .unwrap_or_default();
    levenshtein(original_domain, &candidate_domain)
}

fn tld_priority(original_tld: &str, candidate_fqdn: &str) -> usize {
    let candidate_tld = split_domain_suffix(candidate_fqdn)
        .map(|(_, tld)| tld)
        .unwrap_or_default();
    if candidate_tld == original_tld {
        0
    } else if suffix_family_for(original_tld).contains(&candidate_tld.as_str()) {
        1
    } else if ADD_TLDS.contains(&candidate_tld.as_str()) || ALT_TLDS.contains(&candidate_tld.as_str()) {
        2
    } else {
        3
    }
}

fn levenshtein(a: &str, b: &str) -> usize {
    if a == b {
        return 0;
    }
    if a.is_empty() {
        return b.chars().count();
    }
    if b.is_empty() {
        return a.chars().count();
    }
    let b_chars = b.chars().collect::<Vec<_>>();
    let mut prev = (0..=b_chars.len()).collect::<Vec<_>>();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b_chars.iter().enumerate() {
            let cost = if ca == *cb { 0 } else { 1 };
            cur.push((prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost));
        }
        prev = cur;
    }
    prev[b_chars.len()]
}

fn permute_vowels(values: &mut [char], start: usize, visitor: &mut impl FnMut(Vec<char>)) {
    if start >= values.len() {
        visitor(values.to_vec());
        return;
    }
    for idx in start..values.len() {
        values.swap(start, idx);
        permute_vowels(values, start + 1, visitor);
        values.swap(start, idx);
    }
}

fn apply_replacements(chars: &[char], replacements: &[(usize, &str)]) -> String {
    let mut ordered = replacements.to_vec();
    ordered.sort_by_key(|(idx, _)| *idx);
    let mut out = String::new();
    let mut cursor = 0usize;
    for (idx, replacement) in ordered {
        out.extend(chars[cursor..idx].iter());
        out.push_str(replacement);
        cursor = idx + 1;
    }
    out.extend(chars[cursor..].iter());
    out
}

/// Enumerate up to `max` permutations for a registrable domain (e.g. `example.com`).
pub fn enumerate(apex: &str, max: usize) -> Result<Vec<PermutationLine>, OrifoldError> {
    let (domain, tld) = split_apex(apex)?;
    let apex = format!("{domain}.{tld}");
    let mut generator = Generator::new(apex, domain, tld, max.max(1));
    generator.generate();
    Ok(generator.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_com_yields_variants() {
        let variants = enumerate("example.com", 2000).unwrap();
        assert!(!variants.is_empty());
        assert!(variants.iter().any(|line| line.kind == "Original"));
        assert!(variants.iter().any(|line| line.kind == "Bitsquatting"));
        assert!(variants.iter().any(|line| line.kind == "Replacement"));
        assert!(variants.iter().any(|line| line.kind == "Tld"));
        assert!(variants.iter().any(|line| line.kind == "AddTld"));
        let unique = variants
            .iter()
            .map(|line| line.fqdn.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), variants.len());
        assert!(variants.len() > 500);
    }

    #[test]
    fn invalid_domain_is_rejected() {
        assert!(enumerate("not_a_domain", 20).is_err());
        assert!(enumerate("-example.com", 20).is_err());
    }

    #[test]
    fn numeral_swap_is_supported() {
        let variants = enumerate("circlone.lu", 500).unwrap();
        assert!(variants.iter().any(|line| line.fqdn == "circl1.lu" && line.kind == "NumeralSwap"));
    }

    #[test]
    fn wrong_sld_is_supported_for_common_public_suffixes() {
        let variants = enumerate("trade.co.uk", 500).unwrap();
        assert!(variants.iter().any(|line| line.fqdn == "trade.ac.uk" && line.kind == "WrongSld"));
    }

    #[test]
    fn add_tld_and_strip_dash_are_supported() {
        let variants = enumerate("pay-pal.com", 5000).unwrap();
        assert!(variants.iter().any(|line| line.fqdn == "paypal.com"));
        assert!(variants.iter().any(|line| line.kind == "AddTld"));
    }
}
