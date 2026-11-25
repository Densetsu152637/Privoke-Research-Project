//! `prompt_generation.generator`: seeded training prompts, the held-out partition and the contextual role-quota sampler.
//!
//! Every function draws from one `random.Random` in exactly the order the Python code does, including the lazily
//! produced stochastic retries of `_candidate_seeds`, which interleave with template rendering.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;

use crate::anchor::{self, RehearsalManifest};
use crate::audience::{self, AudienceRelease};
use crate::benign::{self, BenignRelease};
use crate::error::{Result, invalid};
use crate::prompt_seed::{PromptSeed, load_prompt_dataset};
use crate::pyrandom::Random;
use crate::taxonomy::{self, TaxonomyDataset};
use crate::templates::render_template;
use crate::text::training_text_key;
use crate::types::Example;

/// `CONTEXTUAL_SAMPLING_STRATEGY_KEY`.
pub const CONTEXTUAL_SAMPLING_STRATEGY_KEY: &str = "contextual_sampling_strategy";
/// `CONTEXTUAL_ROLE_QUOTA_STRATEGY`.
pub const CONTEXTUAL_ROLE_QUOTA_STRATEGY: &str = "contextual_role_quota_v1";
const AUTHORED_ROLE: &str = "authored_contrastive_context";
const PUBLIC_ROLE: &str = "public_annotation_negative";
const BOOTSTRAP_ROLE: &str = "existing_bootstrap_replay";

/// `_group_id(seed)`: the declared source group, or `None` when absent or blank.
pub fn group_id(seed: &PromptSeed) -> Option<String> {
    seed.metadata.get("group_id").filter(|value| !value.trim().is_empty()).cloned()
}

/// `_candidate_seeds`: every seed once in shuffled order, then bounded stochastic retries, produced lazily.
struct CandidateSeeds {
    order: Vec<usize>,
    position: usize,
    extra: usize,
}

impl CandidateSeeds {
    fn new(len: usize, rng: &mut Random, attempts: usize) -> Self {
        let mut order: Vec<usize> = (0..len).collect();
        rng.shuffle(&mut order);
        Self { extra: attempts.saturating_sub(len), order, position: 0 }
    }

    fn next(&mut self, rng: &mut Random) -> Result<Option<usize>> {
        if self.position < self.order.len() {
            self.position += 1;
            return Ok(Some(self.order[self.position - 1]));
        }
        if self.extra == 0 {
            return Ok(None);
        }
        self.extra -= 1;
        let index = rng.choice_index(self.order.len())?;
        Ok(Some(self.order[index]))
    }
}

fn render_prompt(template: &str, rng: &mut Random) -> Result<String> {
    render_template(template, rng).map_err(|_| crate::error::Error::Invalid("Prompt dataset contains an invalid template.".to_string()))
}

/// `generate_training_prompts(count, seed, dataset_path, excluded_texts=..., excluded_group_ids=...)`.
pub fn generate_training_prompts(
    count: i64,
    seed: u64,
    dataset_path: Option<&Path>,
    excluded_texts: &[String],
    excluded_group_ids: &[String],
) -> Result<Vec<Example>> {
    if count <= 0 {
        return Ok(Vec::new());
    }
    let count = count as usize;
    let mut rng = Random::new(seed);
    let prompt_seeds = load_prompt_dataset(dataset_path)?;
    if prompt_seeds.is_empty() {
        return invalid("Prompt dataset must contain at least one seed.");
    }
    let mut generated: Vec<Example> = Vec::new();
    let excluded: BTreeSet<String> = excluded_texts.iter().map(|text| training_text_key(text)).collect();
    let excluded_groups: BTreeSet<&String> = excluded_group_ids.iter().collect();
    let mut candidates = CandidateSeeds::new(prompt_seeds.len(), &mut rng, 256.max(count * 64));
    while let Some(index) = candidates.next(&mut rng)? {
        if generated.len() == count {
            break;
        }
        let prompt_seed = &prompt_seeds[index];
        let position = generated.len();
        if group_id(prompt_seed).is_some_and(|group| excluded_groups.contains(&group)) {
            continue;
        }
        let text = render_prompt(&prompt_seed.template, &mut rng)?;
        if excluded.contains(&training_text_key(&text)) {
            continue;
        }
        let mut metadata = prompt_seed.metadata.clone();
        metadata.insert("generator".to_string(), "prompt_generation".to_string());
        metadata.insert("generation_index".to_string(), position.to_string());
        metadata.insert("generation_seed".to_string(), seed.to_string());
        metadata.insert("packed_classification".to_string(), prompt_seed.packed().to_string());
        generated.push(Example::new(text, prompt_seed.classification, 1.0, metadata));
    }
    if generated.is_empty() {
        return invalid("Dataset cannot supply training texts separate from held-out data.");
    }
    // Training already samples with replacement; reuse known valid candidates when a fixed dataset is nearly exhausted.
    let available = generated.clone();
    while generated.len() < count {
        let item = rng.choice(&available)?;
        let mut metadata = item.metadata.clone();
        metadata.insert("generation_index".to_string(), generated.len().to_string());
        generated.push(Example { text: item.text.clone(), target: item.target, weight: item.weight, metadata });
    }
    Ok(generated)
}

/// The inputs of `generate_training_partition` beyond the counts and the seed.
#[derive(Debug, Clone, Copy, Default)]
pub struct PartitionSources<'a> {
    /// `dataset_path`.
    pub dataset_path: Option<&'a Path>,
    /// `sampling_strategy`.
    pub sampling_strategy: Option<&'a str>,
    /// `taxonomy_dataset`.
    pub taxonomy_dataset: Option<&'a TaxonomyDataset>,
    /// `rehearsal_manifest`.
    pub rehearsal_manifest: Option<&'a RehearsalManifest>,
    /// `benign_release`.
    pub benign_release: Option<&'a BenignRelease>,
    /// `audience_release`.
    pub audience_release: Option<&'a AudienceRelease>,
}

/// `generate_training_partition(count, heldout_count, seed, ...)`: training examples and the held-out guard.
pub fn generate_training_partition(
    count: i64,
    heldout_count: i64,
    seed: u64,
    sources: &PartitionSources<'_>,
) -> Result<(Vec<Example>, Vec<Example>)> {
    let mut strategy = sources.sampling_strategy;
    if strategy == Some("legacy_random_v1") {
        strategy = None;
    }
    if strategy == Some("audience_coverage_v1") {
        audience::validate_count(count, heldout_count)?;
        if sources.dataset_path.is_some()
            || sources.taxonomy_dataset.is_some()
            || sources.rehearsal_manifest.is_some()
            || sources.benign_release.is_some()
        {
            return invalid("Audience coverage cannot mix legacy source snapshots.");
        }
        let loaded;
        let release = match sources.audience_release {
            Some(release) => release,
            None => {
                loaded = audience::load_release(None, None)?;
                &loaded
            }
        };
        return audience::generate_partition(release, seed, count);
    }
    if sources.audience_release.is_some() {
        return invalid("Audience snapshot requires its explicit strategy.");
    }
    if strategy == Some("taxonomy_benign_coverage_v1") {
        validate_contextual_sampling_strategy(strategy.unwrap_or_default(), count)?;
        let (Some(dataset), Some(release), None) = (sources.taxonomy_dataset, sources.benign_release, sources.rehearsal_manifest) else {
            return invalid("Benign coverage requires its exclusive prepared snapshots and sixteen unchanged guard rows.");
        };
        if heldout_count != 16 {
            return invalid("Benign coverage requires its exclusive prepared snapshots and sixteen unchanged guard rows.");
        }
        return benign::generate_partition(dataset, release, seed);
    }
    if sources.benign_release.is_some() {
        return invalid("Benign release requires its explicit sampling strategy.");
    }
    if strategy == Some("taxonomy_anchor_rehearsal_v1") {
        validate_contextual_sampling_strategy(strategy.unwrap_or_default(), count)?;
        let (Some(dataset), Some(manifest)) = (sources.taxonomy_dataset, sources.rehearsal_manifest) else {
            return invalid("Rehearsal requires prepared dataset/manifest snapshots and sixteen guard rows.");
        };
        if heldout_count != 16 {
            return invalid("Rehearsal requires prepared dataset/manifest snapshots and sixteen guard rows.");
        }
        return anchor::generate_partition(dataset, manifest, seed);
    }
    if sources.rehearsal_manifest.is_some() {
        return invalid("Rehearsal manifest requires its explicit sampling strategy.");
    }
    if strategy == Some("taxonomy_coverage_v1") {
        validate_contextual_sampling_strategy("taxonomy_coverage_v1", count)?;
        if heldout_count != 16 {
            return invalid("Taxonomy coverage requires exactly 16 held-out examples.");
        }
        return match sources.taxonomy_dataset {
            Some(dataset) => taxonomy::generate_partition(dataset, seed),
            None => taxonomy::generate_partition(&taxonomy::load_dataset(sources.dataset_path)?, seed),
        };
    }
    if let Some(strategy) = strategy {
        validate_contextual_sampling_strategy(strategy, count)?;
        if heldout_count != 16 {
            return invalid("Contextual role-quota sampling requires exactly 16 held-out examples.");
        }
    }
    if heldout_count < 2 {
        return invalid("Held-out evaluation needs at least two examples.");
    }
    let mut rng = Random::new(seed + 1);
    let seeds = load_prompt_dataset(sources.dataset_path)?;
    if strategy.is_some() {
        for item in &seeds {
            contextual_role(item)?;
        }
    }
    let groups: [Vec<&PromptSeed>; 2] = [
        seeds.iter().filter(|item| !item.classification.is_sensitive()).collect(),
        seeds.iter().filter(|item| item.classification.is_sensitive()).collect(),
    ];
    if groups.iter().any(Vec::is_empty) {
        return invalid("Held-out evaluation needs both clean and sensitive labels.");
    }
    let mut heldout: Vec<Example> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut reserved_groups: BTreeSet<String> = BTreeSet::new();
    for index in 0..heldout_count {
        let pool = &groups[(index % 2) as usize];
        let mut candidates = CandidateSeeds::new(pool.len(), &mut rng, 256);
        let mut found = false;
        while let Some(choice) = candidates.next(&mut rng)? {
            let item = pool[choice];
            let group = group_id(item);
            if group.as_ref().is_some_and(|group| reserved_groups.contains(group)) {
                continue;
            }
            let text = render_prompt(&item.template, &mut rng)?;
            let key = training_text_key(&text);
            if !seen.contains(&key) {
                seen.insert(key);
                if let Some(group) = group {
                    reserved_groups.insert(group);
                }
                heldout.push(Example::new(text, item.classification, 1.0, item.metadata.clone()));
                found = true;
                break;
            }
        }
        if !found {
            return invalid("Dataset cannot supply enough distinct held-out examples or source groups.");
        }
    }
    let training = if strategy.is_none() {
        let excluded_texts: Vec<String> = heldout.iter().map(|item| item.text.clone()).collect();
        let excluded_groups: Vec<String> = reserved_groups.iter().cloned().collect();
        generate_training_prompts(count, seed, sources.dataset_path, &excluded_texts, &excluded_groups)?
    } else {
        generate_contextual_role_quota(&seeds, seed, &seen, &reserved_groups)?
    };
    Ok((training, heldout))
}

/// `validate_contextual_sampling_strategy(strategy, count)`: fail closed on undeclared modes and their row budget.
pub fn validate_contextual_sampling_strategy(strategy: &str, count: i64) -> Result<()> {
    if strategy == "legacy_random_v1" && count > 0 {
        return Ok(());
    }
    if strategy == "audience_coverage_v1" {
        return audience::validate_count(count, 16);
    }
    if ["taxonomy_coverage_v1", "taxonomy_anchor_rehearsal_v1", "taxonomy_benign_coverage_v1"].contains(&strategy) {
        if count != 32 {
            return invalid("Taxonomy coverage requires exactly 32 training examples.");
        }
        return Ok(());
    }
    if strategy != CONTEXTUAL_ROLE_QUOTA_STRATEGY {
        return invalid("Unsupported contextual sampling strategy.");
    }
    if count != 256 {
        return invalid("Contextual role-quota sampling requires exactly 256 training examples.");
    }
    Ok(())
}

/// `_contextual_role(item)`.
pub fn contextual_role(item: &PromptSeed) -> Result<&str> {
    let role = item.metadata.get("training_role").map(String::as_str);
    let Some(role) = role.filter(|role| [AUTHORED_ROLE, PUBLIC_ROLE, BOOTSTRAP_ROLE].contains(role)) else {
        return invalid("Contextual role-quota dataset contains an unknown training role.");
    };
    if group_id(item).is_none() {
        return invalid("Contextual role-quota sampling requires declared source groups.");
    }
    Ok(role)
}

fn generate_contextual_role_quota(
    seeds: &[PromptSeed],
    seed: u64,
    excluded_texts: &BTreeSet<String>,
    excluded_groups: &BTreeSet<String>,
) -> Result<Vec<Example>> {
    let mut rng = Random::new(seed);
    let mut eligible: Vec<&PromptSeed> = Vec::new();
    for item in seeds {
        if !group_id(item).is_some_and(|group| excluded_groups.contains(&group)) {
            eligible.push(item);
        }
    }
    let mut authored_sensitive = Vec::new();
    let mut authored_clean = Vec::new();
    let mut other = Vec::new();
    for item in &eligible {
        let role = contextual_role(item)?;
        if role == AUTHORED_ROLE {
            if item.classification.is_sensitive() {
                authored_sensitive.push(*item);
            } else {
                authored_clean.push(*item);
            }
        }
        if role == PUBLIC_ROLE || role == BOOTSTRAP_ROLE {
            other.push(*item);
        }
    }
    let partitions: [(Vec<&PromptSeed>, usize); 3] = [(authored_sensitive, 32), (authored_clean, 32), (other, 192)];
    let mut chosen: Vec<Example> = Vec::new();
    let mut seen = excluded_texts.clone();
    for (candidates, quota) in partitions {
        let mut index_of: BTreeMap<String, usize> = BTreeMap::new();
        let mut groups: Vec<Vec<&PromptSeed>> = Vec::new();
        for item in candidates {
            let group = group_id(item).unwrap_or_default();
            let position = *index_of.entry(group).or_insert_with(|| {
                groups.push(Vec::new());
                groups.len() - 1
            });
            groups[position].push(item);
        }
        rng.shuffle(&mut groups);
        for variants in &mut groups {
            rng.shuffle(variants);
        }
        let mut supplied = 0;
        let mut queues: Vec<VecDeque<&PromptSeed>> = groups.into_iter().map(VecDeque::from).collect();
        // Each seed is rendered at most once; collisions inside a group are exhausted before moving on.
        while supplied < quota {
            let mut progressed = false;
            for variants in &mut queues {
                while let Some(item) = variants.pop_front() {
                    let text = render_prompt(&item.template, &mut rng)?;
                    let key = training_text_key(&text);
                    if key.is_empty() || seen.contains(&key) {
                        continue;
                    }
                    seen.insert(key);
                    let mut metadata = item.metadata.clone();
                    metadata.insert("generator".to_string(), "prompt_generation".to_string());
                    metadata.insert("generation_seed".to_string(), seed.to_string());
                    metadata.insert("packed_classification".to_string(), item.packed().to_string());
                    chosen.push(Example::new(text, item.classification, 1.0, metadata));
                    supplied += 1;
                    progressed = true;
                    break;
                }
                if supplied == quota {
                    break;
                }
            }
            if !progressed {
                return invalid("Dataset cannot supply the contextual role quota without replacement.");
            }
        }
    }
    rng.shuffle(&mut chosen);
    let result: Vec<Example> = chosen
        .into_iter()
        .enumerate()
        .map(|(index, mut item)| {
            item.metadata.insert("generation_index".to_string(), index.to_string());
            item
        })
        .collect();
    contextual_sampling_audit(&result)?;
    Ok(result)
}

/// `contextual_sampling_audit(training)`: audit the actually selected rows; counts describe groups, not independent evidence.
pub fn contextual_sampling_audit(training: &[Example]) -> Result<BTreeMap<String, String>> {
    let mut counts: BTreeMap<(String, bool), usize> = BTreeMap::new();
    let mut authored_groups: [BTreeSet<String>; 2] = [BTreeSet::new(), BTreeSet::new()];
    let mut keys = BTreeSet::new();
    for item in training {
        let role = item
            .metadata
            .get("training_role")
            .map(String::as_str)
            .filter(|role| [AUTHORED_ROLE, PUBLIC_ROLE, BOOTSTRAP_ROLE].contains(role));
        let (Some(role), Some(group)) = (role, item.metadata.get("group_id").filter(|group| !group.trim().is_empty())) else {
            return invalid("Contextual role-quota dataset contains an unknown training role.");
        };
        let sensitive = item.classification()?.is_sensitive();
        *counts.entry((role.to_string(), sensitive)).or_default() += 1;
        let key = training_text_key(&item.text);
        if key.is_empty() || !keys.insert(key) {
            return invalid("Contextual role-quota training texts must be distinct and nonempty.");
        }
        if role == AUTHORED_ROLE {
            authored_groups[usize::from(sensitive)].insert(group.clone());
        }
    }
    let count = |role: &str, sensitive: bool| counts.get(&(role.to_string(), sensitive)).copied().unwrap_or(0);
    let authored_sensitive = count(AUTHORED_ROLE, true);
    let authored_clean = count(AUTHORED_ROLE, false);
    let public = count(PUBLIC_ROLE, false) + count(PUBLIC_ROLE, true);
    let bootstrap = count(BOOTSTRAP_ROLE, false) + count(BOOTSTRAP_ROLE, true);
    if training.len() != 256 || authored_sensitive != 32 || authored_clean != 32 || public + bootstrap != 192 {
        return invalid("Actual contextual role-quota selection does not satisfy its declared quotas.");
    }
    let sensitive_rows: usize = counts.iter().filter(|((_, sensitive), _)| *sensitive).map(|(_, value)| value).sum();
    let clean_rows: usize = counts.iter().filter(|((_, sensitive), _)| !*sensitive).map(|(_, value)| value).sum();
    let all_groups: BTreeSet<&String> = authored_groups[0].union(&authored_groups[1]).collect();
    let mut audit = BTreeMap::new();
    audit.insert(CONTEXTUAL_SAMPLING_STRATEGY_KEY.to_string(), CONTEXTUAL_ROLE_QUOTA_STRATEGY.to_string());
    audit.insert("sampling_training_rows".to_string(), training.len().to_string());
    audit.insert("sampling_training_unique_texts".to_string(), keys.len().to_string());
    audit.insert("sampling_authored_sensitive_rows".to_string(), authored_sensitive.to_string());
    audit.insert("sampling_authored_clean_rows".to_string(), authored_clean.to_string());
    audit.insert("sampling_public_negative_rows".to_string(), public.to_string());
    audit.insert("sampling_bootstrap_replay_rows".to_string(), bootstrap.to_string());
    audit.insert("sampling_training_sensitive_rows".to_string(), sensitive_rows.to_string());
    audit.insert("sampling_training_clean_rows".to_string(), clean_rows.to_string());
    audit.insert("sampling_authored_groups".to_string(), all_groups.len().to_string());
    audit.insert("sampling_authored_sensitive_groups".to_string(), authored_groups[1].len().to_string());
    audit.insert("sampling_authored_clean_groups".to_string(), authored_groups[0].len().to_string());
    Ok(audit)
}
