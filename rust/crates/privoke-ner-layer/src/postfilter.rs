//! Post-filter for spaCy NER output (`NER/ner_postfilter.py`).
//!
//! Stage 1 drops candidates that are not real named mentions (placeholder, identifier, structural, short acronym,
//! common phrase). Stage 2 applies the quasi-identifier combination table; the first matching rule per entity decides.
//! Every decision is returned, so the decision log (rule, candidate, outcome) can be compared with Python's.

use std::collections::HashSet;
use std::sync::LazyLock;

use privoke_rules::classification::Sensitivity;
use privoke_rules::pyre::PatternError;
use privoke_spacy::{Analysis, Entity, Selection, Token};

use crate::analyzer::{NerError, SpacyBackend};
use crate::pat::{Pattern, Subject};
use crate::pytext;

const PERSON: &str = "PERSON";
const ORG: &str = "ORG";

fn is_place_label(label: &str) -> bool {
    matches!(label, "GPE" | "LOC" | "FAC")
}

// ---- context cues ---------------------------------------------------------------------------------------------

const POSS_WORDS: [&str; 5] = ["my", "our", "his", "her", "their"];
const POSS: &str = "(?:my|our|his|her|their)";

/// People a speaker stands in a social, family, professional or service relation to.
const ROLE_NOUNS: &str = "mother mom mum mama father dad papa wife husband spouse partner son daughter child kid baby brother sister sibling twin \
cousin uncle aunt nephew niece grandmother grandfather grandma grandpa grandson granddaughter grandparent parent \
friend boss manager supervisor mentor coach teacher tutor professor lecturer advisor adviser counsellor counselor \
therapist psychiatrist psychologist doctor physician dentist surgeon nurse midwife pastor priest rabbi imam \
lawyer attorney solicitor accountant banker landlord landlady tenant roommate flatmate neighbour neighbor colleague coworker \
assistant secretary employee employer client patient student girlfriend boyfriend fiance fiancee ex";

static ROLE_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| ROLE_NOUNS.split_whitespace().collect());

static ROLE_RE: LazyLock<String> = LazyLock::new(|| {
    // Equal-length words never match at the same position, so their order is immaterial; length-descending as Python.
    let mut words: Vec<&str> = ROLE_SET.iter().copied().collect();
    words.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    format!("(?:{})", words.join("|"))
});

const FIELD_NOUNS: &str = r"(?:full\s+name|name|contact|author|patient|client|customer|employee|applicant|student|owner|holder|signatory|recipient|sender|tenant|landlord|signed\s+by|prepared\s+by|submitted\s+by|reported\s+by|attn)";

fn person_cue_source() -> String {
    [
        r"(?:",
        r"\b",
        POSS,
        r"\s+(?:full\s+|legal\s+|first\s+|last\s+|real\s+)?name\s*(?:is|was|:)?",
        r"|\b(?:i\s+am|i'm|im|this\s+is|call\s+me|named|called|name's)",
        r"|\b(?:dear|hi|hello|hey|attn|attention|regards|thanks|thank\s+you|sincerely|cheers|best|signed|cc)\b[,:]?",
        r"|\b(?:mr|mrs|ms|mx|miss|dr|prof|sir|madam|patient|student|client|customer|tenant|employee|applicant|resident)\b\.?",
        r"|\b",
        POSS,
        r"\s+(?:[a-z-]+\s+){0,2}?",
        ROLE_RE.as_str(),
        r"\b[,:]?(?:\s+(?:is|named|called))?",
        r"|\b",
        FIELD_NOUNS,
        "\\s*[:\\-\u{2013}]",
        ")\\s*[,:\\-\u{2013}]?\\s*(?:the\\s+)?$",
    ]
    .concat()
}

fn person_trailing_source() -> String {
    [
        "^(?:['\u{2019}]s\\s+(?:account|email|e-mail|phone|number|address|password|card|record|file|appointment|id|passport|licen[cs]e|insurance|salary|diagnosis|medical|bank|login)",
        r"|,\s*(?:age[d]?\s+)?\d{1,3}\b",
        r"|\s+(?:born|was\s+born|lives|resides|works)\b",
        r"|\s*\(\s*(?:[a-z]+\s+)?",
        FIELD_NOUNS,
        r"\b",
        r"|,?\s+(?:is|was|being)\s+(?:also\s+)?",
        POSS,
        r"\s+(?:[a-z-]+\s+){0,2}?",
        ROLE_RE.as_str(),
        r"\b",
        r"|,\s*",
        POSS,
        r"\s+(?:[a-z-]+\s+){0,2}?",
        ROLE_RE.as_str(),
        r"\b)",
    ]
    .concat()
}

fn role_affiliation_source() -> String {
    [
        r"\b(?:i\s+am|i'm|we're|we\s+are|he's|she's|they're)\s+(?:a|an)\s+(?:[a-z-]+\s+){0,3}?(?:at|for|with)",
        r"|\b",
        POSS,
        r"\s+(?:[a-z'-]+\s+){1,2}(?:at|for|with)",
    ]
    .concat()
}

fn place_relation_source() -> String {
    [
        r"(?:",
        r"\b(?:i|we|he|she|they|you)\s+(?:currently\s+|now\s+|just\s+|recently\s+|still\s+|also\s+)?",
        r"(?:live|lives|living|lived|reside|resides|residing|moved|move|relocated|grew\s+up|was\s+born|were\s+born|",
        r"stay|stays|staying|work|works|worked|working|study|studied|studying)\s*(?:in|at|near|to|around)?",
        r"|\b(?:i\s+am|i'm|we're|we\s+are|he's|she's|they're)\s+(?:currently\s+|originally\s+)?(?:from|in|based\s+in|located\s+in|living\s+in|staying\s+in|born\s+in)",
        r"|\b(?:born|raised|based|living|residing|located)\s+(?:and\s+raised\s+)?in",
        r"|\b",
        POSS,
        r"\s+(?:[a-z]+\s+)?(?:home|house|address|hometown|city|town|neighbou?rhood|apartment|flat|office|location|street|country|branch|store|shop|clinic|school)\s*(?:is|are|:)?\s*(?:in|at|on)?",
        r"|",
        &role_affiliation_source(),
        r")\s*(?:the\s+)?$",
    ]
    .concat()
}

fn org_relation_source() -> String {
    [
        r"(?:",
        r"\b(?:i|we|he|she|they)\s+(?:currently\s+|now\s+|just\s+|recently\s+|still\s+|also\s+)?",
        r"(?:work|works|worked|working|volunteer|volunteers|volunteered|study|studies|studied|studying|intern|interned|interning|",
        r"joined|am\s+employed|is\s+employed|are\s+employed)\s*(?:at|for|with|by)?",
        r"|\bemployed\s+(?:at|by|with)",
        r"|\b(?:i\s+am|i'm|we're|he's|she's|they're)\s+(?:currently\s+)?(?:at|with|from|a\s+member\s+of|enrolled\s+(?:at|in))",
        r"|\b",
        POSS,
        r"\s+(?:[a-z]+\s+)?(?:employer|company|school|university|college|firm|workplace|organi[sz]ation|team|clinic|practice|hospital|bank)\s*(?:is|are|:|,)?\s*(?:called|named)?",
        r"|",
        &role_affiliation_source(),
        r")\s*(?:the\s+)?$",
    ]
    .concat()
}

static SENTENCE_BREAK: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(r#"(?<!\b[mM]r)(?<!\b[mM]rs)(?<!\b[mM]s)(?<!\b[dD]r)(?<!\b[pP]rof)[.!?]+[\"')\]]*\s+|\n\s*\n"#, false));
static PERSON_CUE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(&person_cue_source(), true));
static PERSON_TRAILING_CUE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(&person_trailing_source(), true));
static GEO_CUE: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &[
            r"(?:\b(?:in|from|to|near|at|around|across|within|outside|into|inside|of|toward|towards|visiting|",
            r"moved\s+to|based\s+in|located\s+in|live\s+in|lives\s+in)\s+(?:the\s+)?",
            "|\\b(?:state|city|country|region|province|county|location|address|town|district)\\s*[:=\\-\u{2013}]\\s*)$",
        ]
        .concat(),
        true,
    )
});
static ORG_PREP_CUE: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(r"\b(?:at|for|with|by|from|to|of|joined|via|between)\s+(?:the\s+)?$", true));
static PLACE_RELATION_CUE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(&place_relation_source(), true));
static ORG_RELATION_CUE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(&org_relation_source(), true));
static SPEAKER_TAIL: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"^(?:\s+\w+)?\s*:\s*(.*)$", false));

const FUNCTION_TITLE_WORDS: [&str; 19] =
    ["a", "an", "the", "of", "and", "or", "for", "in", "on", "at", "to", "by", "with", "from", "&", "vs", "de", "la", "le"];

// ---- data model -------------------------------------------------------------------------------------------------

/// A spaCy document: its text and the analysis of the full pipeline.
#[derive(Debug)]
pub struct Doc {
    /// The text spaCy was given, as characters.
    pub chars: Vec<char>,
    /// Tokens (with the dependency parse) and entities.
    pub analysis: Analysis,
    children: Vec<Vec<usize>>,
    left_kids: Vec<usize>,
    right_kids: Vec<usize>,
}

impl Doc {
    /// Builds the document and the child lists of its dependency tree.
    pub fn new(chars: Vec<char>, analysis: Analysis) -> Self {
        let n = analysis.tokens.len();
        let mut children = vec![Vec::new(); n];
        let (mut left_kids, mut right_kids) = (vec![0; n], vec![0; n]);
        for (i, token) in analysis.tokens.iter().enumerate() {
            let head = token.head;
            if head != i && head < n {
                children[head].push(i);
                if i < head {
                    left_kids[head] += 1;
                } else {
                    right_kids[head] += 1;
                }
            }
        }
        Self { chars, analysis, children, left_kids, right_kids }
    }

    fn tokens(&self) -> &[Token] {
        &self.analysis.tokens
    }

    /// Token range `[start, end)` covered by a character span (entities are token aligned).
    pub fn token_range(&self, start_char: usize, end_char: usize) -> (usize, usize) {
        let tokens = self.tokens();
        let start = tokens.partition_point(|t| t.idx < start_char);
        let end = tokens.partition_point(|t| t.idx < end_char);
        (start, end.max(start))
    }

    /// `Span.root`: the token with the shortest path to the sentence root.
    pub fn span_root(&self, start: usize, end: usize) -> Option<usize> {
        let tokens = self.tokens();
        let n = tokens.len();
        if start >= end || end > n {
            return None;
        }
        if let Some(i) = (start..end).find(|&i| tokens[i].head == i) {
            return Some(i);
        }
        let mut best = n;
        let mut root = None;
        for (i, token) in tokens.iter().enumerate().take(end).skip(start) {
            if (start..end).contains(&token.head) {
                continue;
            }
            let words = self.words_to_root(i);
            if words < best {
                best = words;
                root = Some(i);
            }
        }
        Some(root.unwrap_or(start))
    }

    fn words_to_root(&self, index: usize) -> usize {
        let tokens = self.tokens();
        let n = tokens.len();
        let token = &tokens[index];
        let no_kids = self.left_kids[index] == 0 && self.right_kids[index] == 0;
        let chars: Vec<char> = token.text.chars().collect();
        if no_kids && pytext::all_space(&chars) {
            return n - 1;
        }
        if no_kids && !chars.is_empty() && chars.iter().all(|&c| pytext::is_punct(c)) {
            return n - 1;
        }
        let mut steps = 0;
        let mut at = index;
        while tokens[at].head != at {
            at = tokens[at].head;
            steps += 1;
            if steps >= n {
                break;
            }
        }
        steps
    }

    fn line_has_verb(&self, line_start: usize, line_end: usize) -> bool {
        for token in self.tokens() {
            if token.idx >= line_end {
                break;
            }
            if token.idx >= line_start && (token.pos == "VERB" || token.pos == "AUX") {
                return true;
            }
        }
        false
    }
}

/// A spaCy entity with the context features the rules need.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    /// `ent.label_`.
    pub label: String,
    /// `ent.text`.
    pub text: String,
    /// `ent.start_char`.
    pub start: usize,
    /// `ent.end_char`.
    pub end: usize,
    /// First token of the entity.
    pub token_start: usize,
    /// One past its last token.
    pub token_end: usize,
    /// A person cue, recurrence, or place/organisation context cue.
    pub strong_cue: bool,
    /// The span has two or more alphabetic tokens.
    pub multi_token: bool,
    /// A personal-relation cue ties the speaker to the place or organisation.
    pub relation_cue: bool,
    /// A locating or affiliation preposition precedes the span.
    pub geo_or_org_cue: bool,
}

impl Candidate {
    fn text_chars(&self) -> Vec<char> {
        self.text.chars().collect()
    }
}

/// Which stage decided.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Per-span cleaning.
    Span,
    /// Category combination.
    Combination,
}

impl Stage {
    /// `Decision.stage`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Span => "span",
            Self::Combination => "combination",
        }
    }
}

/// Final decision for one candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    /// The candidate.
    pub candidate: Candidate,
    /// Whether the entity is kept.
    pub keep: bool,
    /// The deciding rule (`default` when no combination rule matched).
    pub rule: String,
    /// The deciding stage.
    pub stage: Stage,
    /// `None` keeps the label's default sensitivity.
    pub sensitivity: Option<Sensitivity>,
}

// ---- text helpers ----------------------------------------------------------------------------------------------------

fn before(text: &[char], start: usize, width: usize) -> Result<Vec<char>, PatternError> {
    let window = &text[start.saturating_sub(width)..start.min(text.len())];
    let subject = Subject::new(window);
    let last_end = SENTENCE_BREAK.find_iter(&subject)?.last().map_or(0, |m| m.end);
    Ok(window[last_end..].to_vec())
}

fn after(text: &[char], end: usize, width: usize) -> &[char] {
    pytext::slice(text, end, end + width)
}

fn line_bounds(text: &[char], start: usize, end: usize) -> (usize, usize) {
    let line_start = pytext::rfind_char(text, '\n', start).map_or(0, |i| i + 1);
    let line_end = pytext::find_char(text, '\n', end).unwrap_or(text.len());
    (line_start, line_end)
}

/// `_letters`: the lower-cased alphabetic characters.
fn letters(text: &[char]) -> Vec<char> {
    let mut out = String::new();
    for &c in text {
        if pytext::is_alpha(c) {
            privoke_rules::pyunicode::push_lower(c, &mut out);
        }
    }
    out.chars().collect()
}

/// `re.findall(r"[A-Za-z][A-Za-z'’\-]*", text)` as ranges.
pub(crate) fn alpha_tokens(text: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < text.len() {
        if text[i].is_ascii_alphabetic() {
            let start = i;
            i += 1;
            while i < text.len() && (text[i].is_ascii_alphabetic() || matches!(text[i], '\'' | '\u{2019}' | '-')) {
                i += 1;
            }
            out.push((start, i));
        } else {
            i += 1;
        }
    }
    out
}

fn alpha_token_strings(text: &[char]) -> Vec<Vec<char>> {
    alpha_tokens(text).into_iter().map(|(a, b)| text[a..b].to_vec()).collect()
}

/// `len(re.findall(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", haystack))`.
fn count_bounded(haystack: &[char], needle: &[char]) -> usize {
    let (n, m) = (haystack.len(), needle.len());
    if m == 0 || m > n {
        return 0;
    }
    let mut count = 0;
    let mut i = 0;
    while i + m <= n {
        let bounded_before = i == 0 || !pytext::is_word(haystack[i - 1]);
        let bounded_after = i + m == n || !pytext::is_word(haystack[i + m]);
        if bounded_before && bounded_after && haystack[i..i + m] == *needle {
            count += 1;
            i += m;
        } else {
            i += 1;
        }
    }
    count
}

fn is_recurring(text: &[char], candidate: &Candidate) -> bool {
    let lowered = pytext::lower_chars(text);
    let needle = pytext::lower_chars(&candidate.text_chars());
    if count_bounded(&lowered, &needle) >= 2 {
        return true;
    }
    let cand_chars = candidate.text_chars();
    let tokens: Vec<Vec<char>> = alpha_token_strings(&cand_chars).into_iter().filter(|t| t.len() >= 3).collect();
    if tokens.len() < 2 {
        return false;
    }
    for token in [&tokens[0], &tokens[tokens.len() - 1]] {
        let lowered_token = pytext::lower_chars(token);
        if count_bounded(&lowered, &lowered_token) >= 2 {
            return true;
        }
    }
    false
}

fn possessed_role_head(doc: &Doc, candidate: &Candidate) -> bool {
    let Some(root) = doc.span_root(candidate.token_start, candidate.token_end) else { return false };
    let tokens = doc.tokens();
    if !matches!(tokens[root].dep.as_str(), "appos" | "compound" | "nmod" | "npadvmod" | "conj") {
        return false;
    }
    let head = tokens[root].head;
    if !ROLE_SET.contains(pytext::lower(&tokens[head].lemma).as_str()) {
        return false;
    }
    doc.children[head].iter().any(|&child| tokens[child].dep == "poss" && POSS_WORDS.contains(&tokens[child].lower.as_str()))
}

fn is_speaker_label(text: &[char], candidate: &Candidate) -> Result<bool, PatternError> {
    let line_start = pytext::rfind_char(text, '\n', candidate.start).map_or(0, |i| i + 1);
    let lead = pytext::slice(text, line_start, candidate.start);
    if !pytext::strip_set(lead, &[' ', '\t', '>', '*', '-', '#']).is_empty() {
        return Ok(false);
    }
    let line_end = pytext::find_char(text, '\n', candidate.end);
    let tail = pytext::slice(text, candidate.end, line_end.unwrap_or(text.len()));
    let subject = Subject::new(tail);
    let Some(found) = SPEAKER_TAIL.match_at(&subject, 0)? else { return Ok(false) };
    let (a, b) = found.group(1).unwrap_or((0, 0));
    let rest = pytext::strip(&tail[a..b]);
    Ok(matches!(rest.first(), Some('"' | '\'' | '\u{201c}' | '\u{2018}')) || pytext::split(rest).len() >= 5)
}

fn annotate(doc: &Doc, text: &[char], candidate: &mut Candidate) -> Result<(), PatternError> {
    let before_text = before(text, candidate.start, 90)?;
    let after_text = after(text, candidate.end, 40);
    candidate.multi_token = alpha_tokens(&candidate.text_chars()).len() >= 2;
    let before_subject = Subject::new(&before_text);
    if candidate.label == PERSON {
        candidate.strong_cue = PERSON_CUE.search(&before_subject)?.is_some()
            || PERSON_TRAILING_CUE.match_at(&Subject::new(after_text), 0)?.is_some()
            || possessed_role_head(doc, candidate)
            || is_speaker_label(text, candidate)?
            || is_recurring(text, candidate);
    } else if is_place_label(&candidate.label) {
        candidate.geo_or_org_cue = GEO_CUE.search(&before_subject)?.is_some();
        candidate.relation_cue = PLACE_RELATION_CUE.search(&before_subject)?.is_some();
        candidate.strong_cue = candidate.geo_or_org_cue || candidate.relation_cue;
    } else if candidate.label == ORG {
        candidate.geo_or_org_cue = ORG_PREP_CUE.search(&before_subject)?.is_some();
        candidate.relation_cue = ORG_RELATION_CUE.search(&before_subject)?.is_some();
        candidate.strong_cue = candidate.relation_cue;
    }
    Ok(())
}

// ---- stage 1 ----------------------------------------------------------------------------------------------------------

/// The per-span rules, in order.
pub const SPAN_RULES: [&str; 5] = ["placeholder", "identifier", "structural", "short_acronym", "common_phrase"];

fn placeholder(text: &[char], c: &Candidate) -> bool {
    let cand = c.text_chars();
    let letters = letters(&cand);
    let distinct: HashSet<char> = letters.iter().copied().collect();
    if letters.is_empty() || distinct.len() == 1 {
        return true;
    }
    // re.fullmatch(r"([A-Z])\1*s", c.text.strip()): a capital letter repeated, then a lower-case s.
    let stripped = pytext::strip(&cand);
    if stripped.len() >= 2
        && stripped[0].is_ascii_uppercase()
        && stripped[stripped.len() - 1] == 's'
        && stripped[1..stripped.len() - 1].iter().all(|&x| x == stripped[0])
    {
        return true;
    }
    let open = if c.start > 0 { text.get(c.start - 1).copied() } else { None };
    let close = text.get(c.end).copied();
    match open {
        Some('[') => close == Some(']'),
        Some('<') => close == Some('>'),
        Some('{') => close == Some('}'),
        _ => false,
    }
}

fn identifier(c: &Candidate) -> bool {
    let cand = c.text_chars();
    if cand.contains(&'@')
        || cand.contains(&'_')
        || pytext::contains_str(&cand, "://")
        || pytext::starts_with(&pytext::lower_chars(&cand), "www.")
    {
        return true;
    }
    pytext::split(&cand).iter().any(|token| {
        let digits = token.iter().filter(|&&ch| pytext::is_digit(ch)).count();
        let alphas = token.iter().filter(|&&ch| pytext::is_alpha(ch)).count();
        digits >= 2 && alphas >= 2
    })
}

fn structural(doc: &Doc, text: &[char], c: &Candidate) -> bool {
    if c.label == PERSON && (c.strong_cue || c.multi_token) {
        return false;
    }
    let (line_start, line_end) = line_bounds(text, c.start, c.end);
    let line = &text[line_start..line_end];
    if pytext::lstrip(line).first() == Some(&'#') {
        return true;
    }
    if !line.iter().any(|&ch| pytext::is_upper(ch)) {
        return false;
    }
    let stripped_end = pytext::rstrip(line).last().copied();
    if stripped_end.is_none_or(|ch| matches!(ch, '.' | '!' | '?')) || line.contains(&':') || line.iter().any(|&ch| pytext::is_digit(ch)) {
        return false;
    }
    let tokens = alpha_token_strings(line);
    let own: HashSet<String> = alpha_token_strings(&c.text_chars()).iter().map(|t| pytext::lower(&pytext::string(t))).collect();
    let others = tokens.iter().filter(|t| !own.contains(&pytext::lower(&pytext::string(t)))).count();
    if others < 2 {
        return false;
    }
    let title_ok =
        tokens.iter().all(|t| pytext::is_upper(t[0]) || FUNCTION_TITLE_WORDS.iter().any(|w| *w == pytext::lower(&pytext::string(t))));
    if !title_ok {
        return false;
    }
    !doc.line_has_verb(line_start, line_end)
}

fn short_acronym(text: &[char], c: &Candidate) -> Result<bool, PatternError> {
    let cand = c.text_chars();
    let letters = letters(&cand);
    let before_text = before(text, c.start, 90)?;
    let subject = Subject::new(&before_text);
    if is_place_label(&c.label) && letters.len() <= 3 {
        return Ok(GEO_CUE.search(&subject)?.is_none());
    }
    if c.label == ORG && letters.len() <= 4 && !pytext::strip(&cand).contains(&' ') {
        return Ok(!(ORG_PREP_CUE.search(&subject)?.is_some() || c.relation_cue));
    }
    Ok(false)
}

struct Context<'a, A: SpacyBackend> {
    doc: &'a Doc,
    analyzer: Option<&'a A>,
    lexicon: &'a HashSet<String>,
}

impl<A: SpacyBackend> Context<'_, A> {
    /// True when every word of the span is a lexicon word that the tagger reads as a common word in isolation.
    async fn all_common(&self, c: &Candidate) -> Result<bool, NerError> {
        let Some(analyzer) = self.analyzer else { return Ok(false) };
        if self.lexicon.is_empty() {
            return Ok(false);
        }
        let phrase = pytext::lower(&c.text);
        if alpha_tokens(&phrase.chars().collect::<Vec<_>>()).is_empty() {
            return Ok(false);
        }
        let tagged = analyzer.analyze(&phrase, Selection::TaggerOnly).await?;
        let words: Vec<&Token> = tagged.tokens.iter().filter(|t| t.is_alpha).collect();
        if words.is_empty() {
            return Ok(false);
        }
        Ok(words.iter().all(|t| {
            t.pos != "PROPN" && t.pos != "X" && (self.lexicon.contains(&pytext::lower(&t.lemma)) || self.lexicon.contains(&t.lower))
        }))
    }
}

async fn run_span_rule<A: SpacyBackend>(name: &str, text: &[char], c: &Candidate, ctx: &Context<'_, A>) -> Result<bool, NerError> {
    Ok(match name {
        "placeholder" => placeholder(text, c),
        "identifier" => identifier(c),
        "structural" => structural(ctx.doc, text, c),
        "short_acronym" => short_acronym(text, c)?,
        "common_phrase" => {
            if c.strong_cue || c.label != PERSON || c.multi_token {
                false
            } else {
                ctx.all_common(c).await?
            }
        }
        other => return Err(NerError::SpacyBackend(format!("unknown span rule {other}"))),
    })
}

// ---- stage 2 ------------------------------------------------------------------------------------------------------------

struct Combo {
    persons: Vec<usize>,
    places: Vec<usize>,
    orgs: Vec<usize>,
}

fn independently_corroborated(c: &Candidate) -> bool {
    if c.label == PERSON { c.strong_cue || c.multi_token } else { c.relation_cue }
}

/// The combination rules, in order: `(name, keep, sensitivity)`.
pub const COMBINATION_RULES: [(&str, bool, Option<Sensitivity>); 8] = [
    ("person_linked", true, Some(Sensitivity::S2)),
    ("place_org_linked", true, Some(Sensitivity::S2)),
    ("person_corroborated", true, Some(Sensitivity::S2)),
    ("relation_tied", true, None),
    ("relation_anchored", true, None),
    ("address_shape", true, Some(Sensitivity::S2)),
    ("weak_person", false, None),
    ("lone_place_org", false, None),
];

fn rule_matches(rule: &str, kept: &[Candidate], index: usize, combo: &Combo, text: &[char]) -> bool {
    let c = &kept[index];
    let is_place_or_org = is_place_label(&c.label) || c.label == ORG;
    match rule {
        "person_linked" => {
            if c.label != PERSON {
                return false;
            }
            let partners: Vec<usize> = combo.places.iter().chain(&combo.orgs).copied().collect();
            !partners.is_empty() && (independently_corroborated(c) || partners.iter().any(|&p| independently_corroborated(&kept[p])))
        }
        "place_org_linked" => {
            is_place_or_org
                && !combo.persons.is_empty()
                && (independently_corroborated(c) || combo.persons.iter().any(|&q| independently_corroborated(&kept[q])))
        }
        "person_corroborated" => c.label == PERSON && (c.strong_cue || c.multi_token),
        "relation_tied" => is_place_or_org && c.relation_cue,
        "relation_anchored" => is_place_or_org && combo.places.iter().chain(&combo.orgs).any(|&o| o != index && kept[o].relation_cue),
        "address_shape" => {
            if c.label != "FAC" && c.label != "LOC" {
                return false;
            }
            let mut nearby: Vec<char> = pytext::slice(text, c.start.saturating_sub(8), c.start).to_vec();
            nearby.push(' ');
            nearby.extend_from_slice(pytext::slice(text, c.end, c.end + 8));
            nearby.iter().any(|&ch| pytext::is_decimal(ch))
        }
        "weak_person" => c.label == PERSON,
        "lone_place_org" => is_place_or_org,
        _ => false,
    }
}

fn stage_two(kept: &[Candidate], disabled: &HashSet<String>, weak_person: Option<Sensitivity>, text: &[char]) -> Vec<Decision> {
    let combo = Combo {
        persons: (0..kept.len()).filter(|&i| kept[i].label == PERSON).collect(),
        places: (0..kept.len()).filter(|&i| is_place_label(&kept[i].label)).collect(),
        orgs: (0..kept.len()).filter(|&i| kept[i].label == ORG).collect(),
    };
    let mut decisions = Vec::with_capacity(kept.len());
    for (index, c) in kept.iter().enumerate() {
        let mut decision =
            Decision { candidate: c.clone(), keep: true, rule: "default".to_owned(), stage: Stage::Combination, sensitivity: None };
        for (name, keep, sensitivity) in COMBINATION_RULES {
            if disabled.contains(name) || !rule_matches(name, kept, index, &combo, text) {
                continue;
            }
            let (mut keep, mut sensitivity) = (keep, sensitivity);
            if name == "weak_person" && weak_person.is_some() {
                keep = true;
                sensitivity = weak_person;
            }
            decision = Decision { candidate: c.clone(), keep, rule: name.to_owned(), stage: Stage::Combination, sensitivity };
            break;
        }
        decisions.push(decision);
    }
    decisions
}

// ---- driver -------------------------------------------------------------------------------------------------------------

/// `postfilter(doc, entities, nlp=..., disabled=..., weak_person=...)`.
///
/// `analyzer` is the pipeline that produced `doc` (its tagger re-tags a lower-cased span for the common-word rule);
/// `lexicon` is its lemma-index word list. Without an analyzer that rule never fires. `disabled` names rules to skip.
/// `weak_person` is the sensitivity kept for uncorroborated single names (`Some(S1)` by default, `None` drops them).
pub async fn postfilter<A: SpacyBackend>(
    doc: &Doc,
    entities: &[Entity],
    analyzer: Option<&A>,
    lexicon: &HashSet<String>,
    disabled: &[&str],
    weak_person: Option<Sensitivity>,
) -> Result<Vec<Decision>, NerError> {
    let disabled: HashSet<String> = disabled.iter().map(|s| (*s).to_owned()).collect();
    let text = &doc.chars;
    let mut candidates = Vec::with_capacity(entities.len());
    for ent in entities {
        let (token_start, token_end) = doc.token_range(ent.span.start_char, ent.span.end_char);
        let mut c = Candidate {
            label: ent.label.clone(),
            text: pytext::string(pytext::slice(text, ent.span.start_char, ent.span.end_char)),
            start: ent.span.start_char,
            end: ent.span.end_char,
            token_start,
            token_end,
            strong_cue: false,
            multi_token: false,
            relation_cue: false,
            geo_or_org_cue: false,
        };
        annotate(doc, text, &mut c)?;
        candidates.push(c);
    }
    let ctx = Context { doc, analyzer, lexicon };
    let mut kept = Vec::new();
    let mut decisions = Vec::new();
    for c in candidates {
        let mut dropped_by = None;
        for name in SPAN_RULES {
            if disabled.contains(name) {
                continue;
            }
            if run_span_rule(name, text, &c, &ctx).await? {
                dropped_by = Some(name);
                break;
            }
        }
        match dropped_by {
            None => kept.push(c),
            Some(name) => {
                decisions.push(Decision { candidate: c, keep: false, rule: name.to_owned(), stage: Stage::Span, sensitivity: None })
            }
        }
    }
    decisions.extend(stage_two(&kept, &disabled, weak_person, text));
    decisions.sort_by_key(|d| (d.candidate.start, d.candidate.end));
    Ok(decisions)
}

// ---- caseless input -----------------------------------------------------------------------------------------------------

/// Rules skipped when the prompt carries no case signal. Empty by design (see the Python module).
pub const CASELESS_DISABLED_RULES: [&str; 0] = [];

static PRONOUN_I: LazyLock<Pattern> = LazyLock::new(|| Pattern::new("\\bI\\b(?:['\u{2019}](?:m|ll|ve|d|d've))?", false));

/// `has_case_signal`: lower-case and upper-case letters both occur, ignoring the pronoun "I".
pub fn has_case_signal(text: &[char]) -> Result<bool, PatternError> {
    let subject = Subject::new(text);
    let mut stripped: Vec<char> = Vec::with_capacity(text.len());
    let mut at = 0;
    for m in PRONOUN_I.find_iter(&subject)? {
        stripped.extend_from_slice(&text[at..m.start]);
        stripped.push(' ');
        at = m.end;
    }
    stripped.extend_from_slice(&text[at..]);
    Ok(stripped.iter().any(|&c| pytext::is_upper(c)) && text.iter().any(|&c| pytext::is_lower(c)))
}

/// `fold_case`: lower-case without changing the length, so spans stay valid.
pub fn fold_case(text: &[char]) -> Vec<char> {
    pytext::fold_case(text)
}
