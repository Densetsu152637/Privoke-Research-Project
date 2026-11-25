//! Experimental pattern-based replacement for the spaCy NER layer (`NER/pattern_entity_detector.py`, no ML).
//!
//! Candidates come from cues (field labels, introductions, salutations, honorifics, relations, location and
//! organisation cues), shapes (street addresses, `City, ST 12345`, title-case runs, organisation suffixes), an optional
//! gazetteer, and recurrence of a value already found. Each candidate records its mechanism; overlaps are resolved
//! greedily by mechanism priority and then length. Offsets are code point indexes.

use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use privoke_rules::classification::Classification;
use privoke_rules::pyre::{PatternError, PyMatch};

use crate::analyzer::NerError;
use crate::pat::{Pattern, Subject};
use crate::pytext;
use crate::usecases::use_case;

/// `MODEL_NAME`.
pub const MODEL_NAME: &str = "pattern-entity-detector";

fn priority(mechanism: &str) -> i32 {
    match mechanism {
        "cue" => 0,
        "shape" => 1,
        "gazetteer" | "seed" => 2,
        _ => 3,
    }
}

fn set(words: &'static str) -> HashSet<&'static str> {
    words.split_whitespace().collect()
}

// ---- word lists --------------------------------------------------------------------------------------------------

const FUNCTION_WORDS_TEXT: &str = "
a an the and or but nor so yet if then than that this these those there here
who whom whose which what when where why how while although because since
i me my mine myself we us our ours you your yours he him his she her hers it
its they them their theirs
is am are was were be been being do does did done have has had having
can could will would shall should may might must
not no yes also just really very too only even still already always never
of in on at by for with without from to into onto over under about after before
between during through against around near as per via up down out off
please thanks thank hi hello hey dear ok okay sir madam
some any all each every both either neither many much more most less few other
another such own same
get got make made go going gone come came take took give gave tell told say said
need needs needed want wants wanted like help helps know think see look looking
let use using used write wrote draft send sent
one two three four five six seven eight nine ten
";
const PLACEHOLDERS_TEXT: &str = "
n/a na none unknown redacted anonymous placeholder example test tbd blank
required optional name names first last full middle surname nickname your
email phone address number account id here
";
const MONTHS_DAYS_TEXT: &str = "
january february march april may june july august september october november
december jan feb mar apr jun jul aug sep sept oct nov dec monday tuesday
wednesday thursday friday saturday sunday mon tue tues wed thu thur thurs fri
sat sun
";
const ROLE_WORDS_TEXT: &str = "
manager boss supervisor coworker colleague friend neighbor neighbour landlord
tenant doctor therapist lawyer attorney teacher professor son daughter wife
husband partner spouse mother father mom dad brother sister uncle aunt cousin
nephew niece grandmother grandfather girlfriend boyfriend roommate client
patient student mentor employee assistant nurse child kid baby team desk
department support service services customer hr human resources staff office
admin administrator representative rep agent advisor officer director
president ceo cfo cto hiring recruiter committee board everyone everybody
anyone someone somebody folks guys all there
";
const ORG_WORDS_TEXT: &str = "
inc llc ltd corp corporation co company university college hospital bank clinic
institute foundation group associates partners insurance health systems
technologies school church court agency association authority ministry
department center centre services solutions labs
";
const COMMON_TITLE_WORDS_TEXT: &str = "
social security number card account bank banking credit debit tax medical
records record policy plan benefits insurance driver license licence passport
visa travel booking flight hotel email phone mobile home work personal private
confidential information data privacy password login username api key token
code python java javascript excel word outlook gmail google microsoft apple
amazon facebook instagram twitter linkedin zoom slack teams github docker
windows linux android iphone ios mac internet web website app application
form document file report letter message request support help center
english spanish french german chinese japanese
mr mrs ms miss dr prof
street st avenue ave road rd boulevard blvd drive dr lane ln court ct way
terrace place pl circle parkway highway
north south east west
project review meeting meetings notes summary update updates schedule budget quarterly annual weekly daily
";
const UNIT_WORDS_TEXT: &str = "
minute minutes min mins hour hours day days week weeks month months year years
mile miles km kilometers meter meters foot feet people times items words
dollars dollar percent pages steps ways things more other
";
const ORG_LEAD_STOP_TEXT: &str = "
home night nights weekends weekend days day times nowhere least most once
present school work office the a an my our your their his her this that it
scale scales speed pace random best full max most
what which anything something nothing everything whatever
";
const PLACE_STOP_EXTRA_TEXT: &str = "
home work town city house apartment flat area neighborhood neighbourhood country
state school campus dorm region suburbs suburb office street building
";
const COUNTRIES_TEXT: &str = "
canada mexico brazil argentina chile colombia peru france germany spain italy
portugal ireland england scotland wales netherlands belgium sweden norway
denmark finland poland ukraine russia turkey greece egypt nigeria kenya
ethiopia ghana india pakistan bangladesh china japan korea vietnam thailand
philippines indonesia malaysia singapore australia zealand israel iran iraq
";
const COUNTRIES_EXTRA: [&str; 8] =
    ["united states", "united kingdom", "south africa", "saudi arabia", "new zealand", "south korea", "hong kong", "united arab emirates"];
const CITIES_TEXT: &str = "new york|los angeles|chicago|houston|phoenix|philadelphia|san antonio|san diego\
|dallas|san jose|austin|jacksonville|san francisco|columbus|fort worth\
|indianapolis|charlotte|seattle|denver|boston|detroit|portland|las vegas\
|memphis|baltimore|milwaukee|atlanta|miami|oakland|minneapolis|tampa|orlando\
|toronto|vancouver|montreal|london|paris|berlin|madrid|rome|amsterdam|dublin\
|tokyo|beijing|shanghai|delhi|mumbai|sydney|melbourne";
const GIVEN_NAMES_TEXT: &str = "
james john robert michael william david richard joseph thomas charles daniel
matthew anthony donald steven paul andrew joshua kenneth kevin brian george
timothy ronald edward jason jeffrey ryan jacob gary nicholas eric jonathan
stephen larry justin scott brandon benjamin samuel gregory alexander patrick
frank raymond jack dennis jerry tyler aaron jose adam nathan henry zachary
douglas peter kyle noah ethan jeremy walter christian keith roger terry austin
sean gerald carl harold dylan arthur lawrence jordan jesse bryan billy bruce
gabriel joe logan alan juan albert willie elijah wayne randy vincent philip
eugene russell bobby harry johnny howard evan casey riley sam alex
mary patricia jennifer linda elizabeth barbara susan jessica sarah karen lisa
nancy betty margaret sandra ashley kimberly emily donna michelle carol amanda
dorothy melissa deborah stephanie rebecca sharon laura cynthia kathleen amy
angela shirley anna brenda pamela emma nicole helen samantha katherine
christine debra rachel carolyn janet maria heather diane olivia julie joyce
victoria kelly christina lauren joan evelyn judith megan cheryl andrea hannah
jacqueline martha gloria teresa sara janice marie julia kathryn maya sophia
isabella mia charlotte amelia grace chloe zoe leah lily ella
";
const SURNAMES_TEXT: &str = "
smith johnson williams brown jones garcia miller davis rodriguez martinez
hernandez lopez gonzalez wilson anderson thomas taylor moore jackson martin lee
perez thompson white harris sanchez clark ramirez lewis robinson walker young
allen king wright scott torres nguyen hill flores green adams nelson baker hall
rivera campbell mitchell carter roberts gomez phillips evans turner diaz parker
cruz edwards collins reyes stewart morris morales murphy cook rogers gutierrez
ortiz morgan cooper peterson bailey reed kelly howard ramos kim cox ward
richardson watson brooks chavez wood james bennett gray mendoza ruiz hughes
price alvarez castillo sanders patel myers long ross foster jimenez chen wang
li zhang liu singh kumar khan ali ahmed tan lin huang yang wu
";

/// `_ADDRESS_SUFFIX`: suffix word and its kind (`street` or `amb`).
const ADDRESS_SUFFIX: [(&str, &str); 28] = [
    ("street", "street"),
    ("st", "street"),
    ("avenue", "street"),
    ("ave", "street"),
    ("road", "street"),
    ("rd", "street"),
    ("boulevard", "street"),
    ("blvd", "street"),
    ("drive", "amb"),
    ("dr", "amb"),
    ("lane", "amb"),
    ("ln", "amb"),
    ("court", "amb"),
    ("ct", "amb"),
    ("way", "amb"),
    ("terrace", "amb"),
    ("ter", "amb"),
    ("place", "amb"),
    ("pl", "amb"),
    ("circle", "amb"),
    ("cir", "amb"),
    ("parkway", "street"),
    ("pkwy", "street"),
    ("highway", "street"),
    ("hwy", "street"),
    ("trail", "amb"),
    ("square", "amb"),
    ("sq", "amb"),
];

/// `_US_STATES`, in the dict order of the source.
const US_STATES: [(&str, &str); 51] = [
    ("AL", "alabama"),
    ("AK", "alaska"),
    ("AZ", "arizona"),
    ("AR", "arkansas"),
    ("CA", "california"),
    ("CO", "colorado"),
    ("CT", "connecticut"),
    ("DE", "delaware"),
    ("DC", "district of columbia"),
    ("FL", "florida"),
    ("GA", "georgia"),
    ("HI", "hawaii"),
    ("ID", "idaho"),
    ("IL", "illinois"),
    ("IN", "indiana"),
    ("IA", "iowa"),
    ("KS", "kansas"),
    ("KY", "kentucky"),
    ("LA", "louisiana"),
    ("ME", "maine"),
    ("MD", "maryland"),
    ("MA", "massachusetts"),
    ("MI", "michigan"),
    ("MN", "minnesota"),
    ("MS", "mississippi"),
    ("MO", "missouri"),
    ("MT", "montana"),
    ("NE", "nebraska"),
    ("NV", "nevada"),
    ("NH", "new hampshire"),
    ("NJ", "new jersey"),
    ("NM", "new mexico"),
    ("NY", "new york"),
    ("NC", "north carolina"),
    ("ND", "north dakota"),
    ("OH", "ohio"),
    ("OK", "oklahoma"),
    ("OR", "oregon"),
    ("PA", "pennsylvania"),
    ("RI", "rhode island"),
    ("SC", "south carolina"),
    ("SD", "south dakota"),
    ("TN", "tennessee"),
    ("TX", "texas"),
    ("UT", "utah"),
    ("VT", "vermont"),
    ("VA", "virginia"),
    ("WA", "washington"),
    ("WV", "west virginia"),
    ("WI", "wisconsin"),
    ("WY", "wyoming"),
];
const AMBIGUOUS_ABBR: [&str; 9] = ["ID", "IN", "OR", "ME", "HI", "OK", "LA", "OH", "DE"];
const AMBIGUOUS_PLACES: [&str; 7] = ["georgia", "washington", "indiana", "jordan", "turkey", "chad", "china"];
const BEFORE_CITY_WORDS: [&str; 8] = ["in", "to", "from", "near", "around", "outside", "visit", "visiting"];

static FUNCTION_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(FUNCTION_WORDS_TEXT));
static PLACEHOLDERS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(PLACEHOLDERS_TEXT));
static MONTHS_DAYS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(MONTHS_DAYS_TEXT));
static ROLE_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(ROLE_WORDS_TEXT));
static ORG_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(ORG_WORDS_TEXT));
static COMMON_TITLE_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(COMMON_TITLE_WORDS_TEXT));
static UNIT_WORDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(UNIT_WORDS_TEXT));
static ORG_LEAD_STOP: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(ORG_LEAD_STOP_TEXT));
static GIVEN_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(GIVEN_NAMES_TEXT));
static SURNAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(SURNAMES_TEXT));
static STATE_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| US_STATES.iter().map(|&(_, name)| name).collect());
static COUNTRIES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| set(COUNTRIES_TEXT).into_iter().chain(COUNTRIES_EXTRA).collect());
static CITIES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| CITIES_TEXT.split('|').collect());
static PLACE_STOP: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| FUNCTION_WORDS.iter().copied().chain(set(PLACE_STOP_EXTRA_TEXT)).chain(PLACEHOLDERS.iter().copied()).collect());
static NAME_STOP: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    FUNCTION_WORDS
        .iter()
        .chain(PLACEHOLDERS.iter())
        .chain(MONTHS_DAYS.iter())
        .chain(ROLE_WORDS.iter())
        .chain(ORG_WORDS.iter())
        .copied()
        .collect()
});
static ORG_STOP: LazyLock<HashSet<&'static str>> = LazyLock::new(|| ORG_LEAD_STOP.iter().chain(FUNCTION_WORDS.iter()).copied().collect());

// ---- regular expressions ------------------------------------------------------------------------------------------

const TITLE_TOKEN: &str = r"[A-Z][a-z]+(?:['’\-][A-Z]?[a-z]+)*";
const ZIP: &str = r"\d{5}(?:-\d{4})?";
const B: &str = r"(?<![\w'’])";
const FIELD_DELIM: &str = r"(?:[ \t]*[:=]|[ \t]+[–—\-])[ \t]*";
const REL: &str = "manager|boss|supervisor|co-?worker|colleague|friend|neighbou?r|landlord|tenant|doctor|\
therapist|lawyer|attorney|teacher|professor|son|daughter|wife|husband|partner|spouse|\
mother|father|mom|dad|brother|sister|uncle|aunt|cousin|nephew|niece|grandmother|\
grandfather|girlfriend|boyfriend|roommate|client|patient|student|mentor|employee|\
assistant|nurse|child|kid|baby|fiancee?|ex";
/// The accented branch `fianc[ée]e?` of `_REL`, matched on its own: the slot is any word character, and a match counts
/// only if that character is `é` or `É` in the text (see `cue_matches`). `REL` holds the unaccented rest of the branch.
const REL_ACCENT: &str = r"fianc(\w)e?";
const PERSON_LABELS: &str = r"full[ \t]+name|legal[ \t]+name|first[ \t]+name|last[ \t]+name|sur-?name|family[ \t]+name|(?:patient|customer|employee|tenant|applicant|contact|student|client|account[ \t]*holder|card[ \t]*holder|policy[ \t]*holder|beneficiary|owner|emergency[ \t]+contact)(?:[ \t]+name)?|name|signed|signature|requested[ \t]+by|submitted[ \t]+by|prepared[ \t]+by|written[ \t]+by|attn|attention|reporter|author";
const W: &str = r"[A-Za-z][A-Za-z'’\-]*";
const PII_NOUN: &str = r"(?:ssn|social[ \t]+security|employee|account|passport|policy|dob|date[ \t]+of[ \t]+birth|e-?mail|phone|mobile|id|licen[sc]e|address|insurance|salary|card|contact|callback|mailing)\b";

fn state_abbr() -> String {
    US_STATES.iter().map(|&(abbr, _)| abbr).collect::<Vec<_>>().join("|")
}

fn state_name_re() -> String {
    let mut names: Vec<&str> = US_STATES.iter().map(|&(_, name)| name).collect();
    names.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
    names.iter().map(|n| n.replace(' ', "\\ ")).collect::<Vec<_>>().join("|")
}

fn suffixes() -> String {
    let mut words: Vec<&str> = ADDRESS_SUFFIX.iter().map(|&(w, _)| w).filter(|w| !w.is_empty()).collect();
    words.sort_by_key(|w| std::cmp::Reverse(w.len()));
    words.join("|")
}

static TITLE_RUN: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(&format!(r"(?<![\w'’])({TITLE_TOKEN}(?:[ \t]+(?:[A-Z]\.[ \t]*)?{TITLE_TOKEN}){{1,2}})(?![\w])"), false));
static REGION_TAIL: LazyLock<Pattern> = LazyLock::new(|| {
    let (abbr, names) = (state_abbr(), state_name_re());
    let lowabbr = abbr.to_lowercase();
    Pattern::new(
        &format!(r"[ \t]*,[ \t]*(?:(?P<abbr>{abbr})|(?P<lowabbr>{lowabbr})(?=[ \t]+{ZIP})|(?P<name>{names}))\b(?:[ \t]+(?P<zip>{ZIP}))?"),
        true,
    )
});
static STREET: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(r"(?<![\w.#-])(?P<num>\d{{1,6}})[ \t]+(?P<mid>(?:[A-Za-z0-9'’.\-]+[ \t]+){{1,4}}?)(?P<suffix>{})\b", suffixes()),
        true,
    )
});
static TITLE_STREET: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(
            r"(?<![\w'’])(?:{TITLE_TOKEN}[ \t]+){{1,2}}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Lane|Court|Way|Terrace|Parkway|Highway)\b"
        ),
        false,
    )
});
static ORG_SUFFIX_TITLE: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(
            r"(?<![\w'’])((?:{TITLE_TOKEN}[ \t]+){{1,3}}(?:Inc|LLC|Ltd|Corp|Corporation|Co|Company|University|College|Hospital|Bank|Clinic|Institute|Foundation|Group|Associates|Partners|Insurance|Technologies|Systems|Labs|Church|School))\b"
        ),
        false,
    )
});
static ORG_PREFIX_TITLE: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(
        &format!(
            r"(?<![\w'’])((?:Bank|University|College|Institute|Hospital|Church|Department|City|County|State)[ \t]+of[ \t]+(?:{TITLE_TOKEN})(?:[ \t]+{TITLE_TOKEN})?)"
        ),
        false,
    )
});
static ORG_LEGAL_ANY_CASE: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(r"(?<![\w'’])((?:[A-Za-z][\w&'’\-]*[ \t]+){1,3}(?:inc|llc|ltd|corp|plc|gmbh))\b", true));
static ORG_PREFIX_ANY_CASE: LazyLock<Pattern> = LazyLock::new(|| {
    Pattern::new(r"(?<![\w'’])((?:university|college|bank|institute)[ \t]+of[ \t]+[A-Za-z][\w'’\-]*(?:[ \t]+[A-Za-z][\w'’\-]*)?)", true)
});
static CITY: LazyLock<Pattern> =
    LazyLock::new(|| Pattern::new(&format!(r"(?<![\w'’])({TITLE_TOKEN}(?:[ \t]+{TITLE_TOKEN}){{0,2}})(?=[ \t]*,[ \t]*)"), false));
static LOWER_CITY: LazyLock<Pattern> = LazyLock::new(|| {
    let lowabbr = state_abbr().to_lowercase();
    Pattern::new(&format!(r"(?<![\w'’])([a-z][a-z\-]+(?:[ \t]+[a-z][a-z\-]+){{0,2}})(?=[ \t]*,[ \t]*(?:{lowabbr})[ \t]+{ZIP})"), false)
});
static STREET_TAIL: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"[ \t]*,[ \t]*", false));
static LEAD_THE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"[ \t]*the[ \t]+", true));
static FOLLOWING_WORD: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"[ \t]*([A-Za-z]+)", false));
static TITLE_RECORD_TAIL: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"[ \t]*,[^\n]{0,40}?[\d@]", false));
static BULLET_BEFORE: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"(?:^|\n)[ \t]*(?:[-*•]|\d+[.)])$", false));
static GIVEN_PAIR: LazyLock<Pattern> = LazyLock::new(|| Pattern::new(r"(?<![\w'’])([A-Za-z][a-z]+)[ \t]+([A-Za-z][a-z]+)(?![\w])", false));

/// A cue: the pattern that introduces a value, what the value is, and how to read it.
struct Cue {
    name: &'static str,
    pattern: Pattern,
    /// For the two relation cues: the same pattern with `_REL` reduced to its accented branch.
    accent: Option<Pattern>,
    label: &'static str,
    scan: Scan,
    allow_lower: bool,
    max_tokens: usize,
    allow_cap: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scan {
    Name,
    Place,
    Org,
}

fn cue(
    name: &'static str,
    regex: String,
    label: &'static str,
    scan: Scan,
    allow_lower: bool,
    max_tokens: usize,
    flags_ignore_case: bool,
) -> Cue {
    let allow_cap = true;
    Cue { name, pattern: Pattern::new(&regex, flags_ignore_case), accent: None, label, scan, allow_lower, max_tokens, allow_cap }
}

fn with_accent(mut cue: Cue, regex: String) -> Cue {
    cue.accent = Some(Pattern::new(&regex, true));
    cue
}

static CUES: LazyLock<Vec<Cue>> = LazyLock::new(|| {
    use Scan::{Name, Org, Place};
    let rel = REL;
    let cues = vec![
        cue("field_name", format!(r"{B}(?:{PERSON_LABELS}){FIELD_DELIM}"), "PERSON", Name, true, 3, true),
        cue(
            "role_prefix",
            format!(
                r"{B}(?:student|patient|customer|client|employee|tenant|applicant|member|resident|claimant|passenger|candidate|beneficiary|cardholder|policyholder)[ \t]+"
            ),
            "PERSON",
            Name,
            false,
            3,
            true,
        ),
        cue(
            "self_intro_my_name",
            format!(r"{B}my[ \t]+(?:(?:full|legal|first|last)[ \t]+)?name(?:[ \t]+is|['’]s)[ \t]+"),
            "PERSON",
            Name,
            true,
            3,
            true,
        ),
        cue(
            "self_intro_call_me",
            format!(r"{B}(?:(?:you[ \t]+can|please|just)[ \t]+)?(?:call|address)[ \t]+me[ \t]+"),
            "PERSON",
            Name,
            true,
            3,
            true,
        ),
        cue(
            "self_intro_called",
            format!(
                r"{B}(?:i[ \t]+am|i['’]m|im|they[ \t]+call[ \t]+me|known[ \t]+as|go[ \t]+by)[ \t]+(?:called|named|known[ \t]+as)?[ \t]*"
            ),
            "PERSON",
            Name,
            false,
            3,
            true,
        ),
        cue(
            "self_intro_this_is",
            format!(r"{B}(?:this[ \t]+is|it['’]s|hi,?[ \t]+i['’]m|my[ \t]+name['’]s)[ \t]+"),
            "PERSON",
            Name,
            false,
            3,
            true,
        ),
        cue("named", format!(r"{B}(?:named|nicknamed|under[ \t]+the[ \t]+name)[ \t]+"), "PERSON", Name, false, 3, true),
        cue("salutation_dear", format!(r"{B}dear[ \t]+(?:(?:mr|mrs|ms|miss|dr|prof)\.?[ \t]+)?"), "PERSON", Name, true, 3, true),
        cue("salutation_greeting", format!(r"{B}(?:hi|hello|hey|greetings)[ \t]+"), "PERSON", Name, false, 3, true),
        cue(
            "signoff",
            format!(
                r"{B}(?:(?:best|kind|warm|many|with|sincere)[ \t]+)?(?:regards|sincerely|thanks|thank[ \t]+you|cheers|respectfully|yours[ \t]+(?:truly|sincerely|faithfully))[ \t]*[,.!]?[ \t]*\r?\n[ \t]*[\-–—~]?[ \t]*"
            ),
            "PERSON",
            Name,
            true,
            3,
            true,
        ),
        cue("honorific_period", format!(r"{B}(?:mr|mrs|ms|miss|mx|dr|prof|mister)\.[ \t]*"), "PERSON", Name, true, 2, true),
        cue("honorific_word", format!(r"{B}(?:mr|mrs|dr|prof|professor|mister)[ \t]+"), "PERSON", Name, true, 2, true),
        cue("honorific_title_case", format!(r"{B}(?:Ms|Miss|Mx)[ \t]+"), "PERSON", Name, false, 2, false),
        with_accent(
            cue(
                "relation_named",
                format!(
                    r"{B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{rel})[ \t]*,?[ \t]*(?:named|called)[ \t]+"
                ),
                "PERSON",
                Name,
                true,
                3,
                true,
            ),
            format!(
                r"{B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{REL_ACCENT})[ \t]*,?[ \t]*(?:named|called)[ \t]+"
            ),
        ),
        with_accent(
            cue(
                "relation_apposition",
                format!(
                    r"{B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{rel})(?:[ \t]*,[ \t]*|[ \t]+(?:is|was)[ \t]+|[ \t]+)"
                ),
                "PERSON",
                Name,
                false,
                3,
                true,
            ),
            format!(
                r"{B}(?:my|our|his|her|their)[ \t]+(?:(?:ex|step|half|future|late|former)[ \t\-])?(?:{REL_ACCENT})(?:[ \t]*,[ \t]*|[ \t]+(?:is|was)[ \t]+|[ \t]+)"
            ),
        ),
        cue(
            "agent_by",
            format!(r"{B}(?:signed|submitted|prepared|written|authored|sent|created|reported|approved)[ \t]+by[ \t]+"),
            "PERSON",
            Name,
            true,
            3,
            true,
        ),
        cue("on_behalf", format!(r"{B}on[ \t]+behalf[ \t]+of[ \t]+"), "PERSON", Name, false, 3, true),
        cue(
            "residence_verb",
            format!(
                r"{B}(?:(?:i|we|he|she|they)[ \t]+(?:(?:am|are|is|was|were|have|has)[ \t]+)?|(?:i['’]m|we['’]re|he['’]s|she['’]s|they['’]re|im)[ \t]+)(?:currently[ \t]+|now[ \t]+|still[ \t]+|recently[ \t]+)?(?:live[sd]?|living|reside[sd]?|residing|located|based|stay(?:s|ing)?|moved|relocated|relocating|born|raised|grew[ \t]+up|stationed|headquartered)[ \t]+(?:in|at|near|to|on|from|around)[ \t]+"
            ),
            "GPE",
            Place,
            true,
            3,
            true,
        ),
        cue(
            "from_place",
            format!(r"{B}(?:i['’]m|i[ \t]+am|im|we['’]re|he['’]s|she['’]s)[ \t]+(?:originally[ \t]+)?from[ \t]+"),
            "GPE",
            Place,
            false,
            3,
            true,
        ),
        cue(
            "lives_in",
            format!(r"{B}(?:live[sd]?|living|resid(?:e|es|ed|ing)|based|located|born|raised)[ \t]+(?:in|at|near)[ \t]+"),
            "GPE",
            Place,
            true,
            3,
            true,
        ),
        cue(
            "field_place",
            format!(
                r"{B}(?:city|town|state|province|country|hometown|birthplace|place[ \t]+of[ \t]+birth|residence|current[ \t]+location|home[ \t]+location){FIELD_DELIM}"
            ),
            "GPE",
            Place,
            true,
            3,
            true,
        ),
        cue(
            "my_location",
            format!(
                r"{B}(?:my|our|his|her|their)[ \t]+(?:home[ \t]+)?(?:hometown|residence|city|birthplace|place[ \t]+of[ \t]+birth)[ \t]*(?:is|was|[:=])[ \t]*"
            ),
            "GPE",
            Place,
            true,
            3,
            true,
        ),
        cue(
            "works_at",
            format!(
                r"{B}(?:work(?:s|ed|ing)?|employed|interning|intern(?:ed)?|volunteer(?:s|ed|ing)?|consult(?:s|ed|ing)?)[ \t]+(?:at|for|with|by)[ \t]+(?:the[ \t]+)?"
            ),
            "ORG",
            Org,
            true,
            4,
            true,
        ),
        cue(
            "employer_field",
            format!(
                r"{B}(?:employer|company|organi[sz]ation|school|university|college|workplace|insurer|insurance[ \t]+(?:company|provider)|bank|hospital|clinic)(?:[ \t]+name)?[ \t]*(?:[:=–—]|\-|is|was)[ \t]+(?:the[ \t]+)?"
            ),
            "ORG",
            Org,
            true,
            4,
            true,
        ),
        cue(
            "studies_at",
            format!(
                r"{B}(?:student|enrolled|studying|study|studied|graduated|alumn\w+|attend(?:s|ed|ing)?)[ \t]+(?:at|from|in)[ \t]+(?:the[ \t]+)?"
            ),
            "ORG",
            Org,
            true,
            4,
            true,
        ),
        cue(
            "customer_of",
            format!(
                r"{B}(?:bank(?:s|ed|ing)?[ \t]+with|insured[ \t]+(?:by|with|through)|insurance[ \t]+(?:with|through|from)|treated[ \t]+at|admitted[ \t]+to|patient[ \t]+at|account[ \t]+(?:at|with))[ \t]+(?:the[ \t]+)?"
            ),
            "ORG",
            Org,
            true,
            4,
            true,
        ),
    ];
    cues
});

/// Adjacent patterns: `(pattern, cue name, accepts lowercase runs)`; group 1 is the name candidate.
static ADJACENT: LazyLock<Vec<(Pattern, &'static str, bool)>> = LazyLock::new(|| {
    vec![
        (Pattern::new(&format!(r"(?<![\w'’])(?P<run>(?:{W}[ \t]+)?{W})['’]s[ \t]+{PII_NOUN}"), true), "possessive_pii_noun", true),
        (
            Pattern::new(&format!(r"(?<![\w'’])(?P<run>(?:{W}[ \t]+){{0,2}}{W})[ \t]*,[ \t]*(?:{PII_NOUN}|[\w.+\-]+@)"), true),
            "record_pii_noun",
            true,
        ),
        (
            Pattern::new(
                &format!(
                    r"(?:for|to|about|regarding)[ \t]+(?P<run>{W}[ \t]+{W})[ \t]*[.,:;][ \t]*(?:(?:the|my|his|her|their)[ \t]+)?{PII_NOUN}"
                ),
                true,
            ),
            "benefactive_pii_noun",
            false,
        ),
    ]
});

// ---- data model ---------------------------------------------------------------------------------------------------

/// A candidate value: its span, label and the mechanism that found it.
#[derive(Clone, Debug, PartialEq)]
struct Candidate {
    start: usize,
    end: usize,
    label: String,
    mechanism: &'static str,
    cue: String,
}

impl Candidate {
    fn new(start: usize, end: usize, label: &str, mechanism: &'static str, cue: &str) -> Self {
        Self { start, end, label: label.to_owned(), mechanism, cue: cue.to_owned() }
    }

    fn key(&self) -> (i32, isize) {
        (priority(self.mechanism), -((self.end as isize) - (self.start as isize)))
    }
}

/// A seed for hybrid mode: an already found value (for example a spaCy result) with its span and label.
#[derive(Clone, Debug, PartialEq)]
pub struct Seed {
    /// `result.span`.
    pub span: Option<(usize, usize)>,
    /// `metadata["label"]`.
    pub label: Option<String>,
}

/// One value the detector found.
#[derive(Clone, Debug, PartialEq)]
pub struct PatternResult {
    /// `metadata["label"]`.
    pub label: String,
    /// `metadata["entity_type"]`.
    pub entity_type: &'static str,
    /// `metadata["mechanism"]`.
    pub mechanism: &'static str,
    /// `metadata["cue"]`.
    pub cue: String,
    /// The span.
    pub span: (usize, usize),
    /// `section_of_text`.
    pub text: String,
    /// The packed classification.
    pub classification: Classification,
    /// Confidence.
    pub confidence: f64,
    /// `reasoning`.
    pub reasoning: String,
}

/// An output item: a value found here, or a seed returned unchanged (its index in the seeds given).
#[derive(Clone, Debug, PartialEq)]
pub enum PatternOutput {
    /// A result built by the detector.
    Found(PatternResult),
    /// A seed, unchanged.
    Seed(usize),
}

/// Which mechanisms run (`use_cues`, `use_shape`, `use_recurrence`, `use_gazetteer`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PatternOptions {
    /// Cue candidates.
    pub use_cues: bool,
    /// Shape candidates.
    pub use_shape: bool,
    /// Recurrence of a value already found.
    pub use_recurrence: bool,
    /// The closed-class gazetteer (off by default).
    pub use_gazetteer: bool,
}

impl Default for PatternOptions {
    fn default() -> Self {
        Self { use_cues: true, use_shape: true, use_recurrence: true, use_gazetteer: false }
    }
}

// ---- helpers ---------------------------------------------------------------------------------------------------------

fn lower(chars: &[char]) -> String {
    pytext::lower(&pytext::string(chars))
}

/// `_fold`: lower-case without changing the length.
fn fold(chars: &[char]) -> Vec<char> {
    pytext::fold_case(chars)
}

/// `_strip_possessive(token)`.
fn strip_possessive(token: &str) -> (String, bool) {
    let chars: Vec<char> = token.chars().collect();
    let lowered: Vec<char> = pytext::lower_chars(&chars);
    for suffix in ["'s", "\u{2019}s", "'", "\u{2019}"] {
        let s: Vec<char> = suffix.chars().collect();
        if lowered.len() >= s.len() && lowered[lowered.len() - s.len()..] == s[..] && chars.len() > s.len() + 1 {
            return (pytext::string(&chars[..chars.len() - s.len()]), true);
        }
    }
    (token.to_owned(), false)
}

/// `re.sub(r"[^a-z]", "", w.lower())`.
fn letters_a_z(word: &str) -> String {
    pytext::lower(word).chars().filter(char::is_ascii_lowercase).collect()
}

/// `_TOKEN.match(text, i)`: `[ \t]*([A-Za-z][A-Za-z'’\-]*)(\.?)`. Returns `(word start, word end, dot end, match end)`.
fn token_match(text: &[char], at: usize) -> Option<(usize, usize, Option<usize>, usize)> {
    let mut i = at;
    while i < text.len() && matches!(text[i], ' ' | '\t') {
        i += 1;
    }
    if i >= text.len() || !text[i].is_ascii_alphabetic() {
        return None;
    }
    let start = i;
    i += 1;
    while i < text.len() && (text[i].is_ascii_alphabetic() || matches!(text[i], '\'' | '\u{2019}' | '-')) {
        i += 1;
    }
    if i < text.len() && text[i] == '.' { Some((start, i, Some(i + 1), i + 1)) } else { Some((start, i, None, i)) }
}

fn str_is_upper(chars: &[char]) -> bool {
    chars.iter().any(|&c| pytext::is_upper(c)) && !chars.iter().any(|&c| pytext::is_lower(c))
}

fn scan_value(
    text: &[char],
    subject: &Subject,
    pos: usize,
    scan: Scan,
    max_tokens: usize,
    allow_lower: bool,
    allow_cap: bool,
) -> Result<Option<(usize, usize)>, PatternError> {
    let stop: &HashSet<&'static str> = match scan {
        Scan::Name => &NAME_STOP,
        Scan::Place => &PLACE_STOP,
        Scan::Org => &ORG_STOP,
    };
    let mut mode: Option<bool> = None; // Some(true) = capitalised run
    let mut first = None;
    let mut end = None;
    let mut count = 0;
    let mut i = pos;
    if scan != Scan::Name
        && let Some(lead) = LEAD_THE.match_at(subject, i)?
    {
        i = lead.end;
    }
    while count < max_tokens {
        let Some((word_start, word_end, dot_end, match_end)) = token_match(text, i) else { break };
        let raw: String = pytext::string(&text[word_start..word_end]);
        let (word, possessive) = strip_possessive(&raw);
        let word_chars: Vec<char> = word.chars().collect();
        let low = pytext::lower(&word);
        let is_cap = pytext::is_upper(word_chars[0]);
        let current = match mode {
            None => {
                mode = Some(is_cap);
                if (is_cap && !allow_cap) || (!is_cap && !allow_lower) {
                    return Ok(None);
                }
                is_cap
            }
            Some(m) => m,
        };
        if current != is_cap {
            break;
        }
        let dot = dot_end.is_some();
        if scan == Scan::Name && count > 0 && word_chars.len() == 1 && dot {
            // middle initial
        } else if word_chars.len() < 2 || stop.contains(low.as_str()) {
            break;
        }
        if scan == Scan::Name && count == 0 && low.ends_with("ing") && low.chars().count() > 5 {
            break;
        }
        if scan == Scan::Name && COMMON_TITLE_WORDS.contains(low.as_str()) && current && count == 0 && !GIVEN_NAMES.contains(low.as_str()) {
            break;
        }
        if first.is_none() {
            first = Some(word_start);
        }
        end = Some(word_start + word_chars.len());
        count += 1;
        i = word_end;
        if dot && word_chars.len() == 1 {
            end = dot_end;
            i = match_end;
        }
        if possessive {
            break;
        }
    }
    let (Some(first), Some(mut end)) = (first, end) else { return Ok(None) };
    if scan == Scan::Name && pytext::strip(pytext::slice(text, first, end)).last() == Some(&'.') {
        end = pytext::rstrip_set(&text[..end.min(text.len())], &['.']).len();
    }
    Ok(Some((first, end)))
}

fn extend_region(subject: &Subject, end: usize) -> Result<usize, PatternError> {
    let Some(m) = REGION_TAIL.match_at(subject, end)? else { return Ok(end) };
    let text = subject.chars();
    let abbr = m.group(1).map(|(a, b)| &text[a..b]);
    let zip = m.group(4);
    if let Some(abbr) = abbr {
        if !(str_is_upper(abbr) || zip.is_some()) {
            return Ok(end);
        }
        let upper = privoke_rules::pyunicode::upper(&pytext::string(abbr));
        if AMBIGUOUS_ABBR.contains(&upper.as_str()) && zip.is_none() {
            return Ok(end);
        }
    }
    Ok(m.end)
}

fn sentence_start(text: &[char], pos: usize) -> Result<bool, PatternError> {
    let before = pytext::rstrip_set(&text[..pos.min(text.len())], &[' ', '\t']);
    let Some(&last) = before.last() else { return Ok(true) };
    if matches!(last, '.' | '!' | '?' | ':' | ';' | '\n' | '\r' | '"' | '\u{201c}' | '(') {
        return Ok(true);
    }
    Ok(BULLET_BEFORE.search(&Subject::new(before))?.is_some())
}

/// `(?<!\w'’)needle(?!\w)`-style literal search; `before_extra` and `after_extra` add characters to the lookarounds.
fn find_bounded(haystack: &[char], needle: &[char], before_extra: &[char], after_extra: &[char]) -> Vec<(usize, usize)> {
    let (n, m) = (haystack.len(), needle.len());
    let mut out = Vec::new();
    if m == 0 || m > n {
        return out;
    }
    let mut i = 0;
    while i + m <= n {
        let ok_before = i == 0 || !(pytext::is_word(haystack[i - 1]) || before_extra.contains(&haystack[i - 1]));
        let ok_after = i + m == n || !(pytext::is_word(haystack[i + m]) || after_extra.contains(&haystack[i + m]));
        if ok_before && ok_after && haystack[i..i + m] == *needle {
            out.push((i, i + m));
            i += m;
        } else {
            i += 1;
        }
    }
    out
}

/// `cue.pattern.finditer(text)`. The relation cues name `é` (`fianc[ée]e?`), which the shadow text cannot tell from other
/// non-ASCII word characters. The main pattern therefore holds the unaccented branch (`fiancee?`), and `accent` holds
/// the accented branch alone with `\w` in the `[ée]` slot; a match of `accent` counts only if the text has `é` or `É`
/// in that slot. Python's alternatives are different words, so at one start at most one of the two matches, and the
/// leftmost of them is the match Python finds.
fn cue_matches(cue: &Cue, subject: &Subject) -> Result<Vec<PyMatch>, PatternError> {
    let Some(accent) = &cue.accent else { return cue.pattern.find_iter(subject) };
    let chars = subject.chars();
    let mut out = Vec::new();
    let mut pos = 0;
    while pos <= chars.len() {
        let plain = cue.pattern.search_from(subject, pos)?;
        let mut accented = None;
        let mut from = pos;
        while let Some(m) = accent.search_from(subject, from)? {
            if plain.as_ref().is_some_and(|p| m.start >= p.start) {
                break;
            }
            if let Some((a, b)) = m.group(1)
                && b == a + 1
                && matches!(chars[a], '\u{e9}' | '\u{c9}')
            {
                accented = Some(m);
                break;
            }
            from = m.start + 1;
        }
        let Some(chosen) = accented.or(plain) else { break };
        pos = if chosen.end == chosen.start { chosen.end + 1 } else { chosen.end };
        out.push(chosen);
    }
    Ok(out)
}

// ---- the detector --------------------------------------------------------------------------------------------------------

/// Regex-style entity extraction with the `EntityNERDetector` contract.
#[derive(Clone, Copy, Debug, Default)]
pub struct PatternEntityDetector {
    /// Which mechanisms run.
    pub options: PatternOptions,
}

impl PatternEntityDetector {
    /// A detector with the given mechanisms.
    pub fn new(options: PatternOptions) -> Self {
        Self { options }
    }

    /// `extract_entities(text)`.
    pub fn extract_entities(&self, text: &str) -> Result<Vec<PatternOutput>, NerError> {
        self.run(text, &[])
    }

    /// `augment_entities(text, seeds)`: hybrid mode.
    pub fn augment_entities(&self, text: &str, seeds: &[Seed]) -> Result<Vec<PatternOutput>, NerError> {
        self.run(text, seeds)
    }

    fn run(&self, text: &str, seeds: &[Seed]) -> Result<Vec<PatternOutput>, NerError> {
        if text.is_empty() {
            return Ok((0..seeds.len()).map(PatternOutput::Seed).collect());
        }
        let chars: Vec<char> = text.chars().collect();
        let subject = Subject::new(&chars);
        let mut candidates: Vec<Candidate> = Vec::new();
        for seed in seeds {
            if let (Some((start, end)), Some(label)) = (seed.span, seed.label.as_deref())
                && use_case(label).is_some()
            {
                candidates.push(Candidate::new(start, end, label, "seed", "seed"));
            }
        }
        if self.options.use_cues {
            candidates.extend(self.cue_candidates(&chars, &subject)?);
        }
        if self.options.use_shape {
            candidates.extend(self.shape_candidates(&chars, &subject)?);
        }
        if self.options.use_gazetteer {
            candidates.extend(self.gazetteer_candidates(&chars, &subject)?);
        }
        let mut selected = resolve(candidates);
        if self.options.use_recurrence {
            let mut more = selected.clone();
            more.extend(self.recurrence_candidates(&chars, &subject, &selected)?);
            selected = resolve(more);
        }
        // by_span = {(span, label): seed} keeps the last seed for a key.
        let mut by_span: HashMap<((usize, usize), String), usize> = HashMap::new();
        for (index, seed) in seeds.iter().enumerate() {
            if let Some(span) = seed.span {
                by_span.insert((span, seed.label.clone().unwrap_or_default()), index);
            }
        }
        let mut out = Vec::with_capacity(selected.len());
        for cand in selected {
            if cand.mechanism == "seed" {
                let index = by_span
                    .get(&((cand.start, cand.end), cand.label.clone()))
                    .copied()
                    .ok_or_else(|| NerError::SpacyBackend("seed not found".to_owned()))?;
                out.push(PatternOutput::Seed(index));
            } else {
                out.push(PatternOutput::Found(result(&chars, &cand)?));
            }
        }
        Ok(out)
    }

    // ---- cues ----

    fn cue_candidates(&self, text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
        let mut found = Vec::new();
        for cue in CUES.iter() {
            for m in cue_matches(cue, subject)? {
                let Some((start, mut end)) = scan_value(text, subject, m.end, cue.scan, cue.max_tokens, cue.allow_lower, cue.allow_cap)?
                else {
                    continue;
                };
                if cue.scan == Scan::Name && !plausible_name(text, start, end)? {
                    continue;
                }
                if cue.scan == Scan::Place {
                    end = extend_region(subject, end)?;
                }
                if cue.scan == Scan::Org && !plausible_org(pytext::slice(text, start, end)) {
                    continue;
                }
                found.push(Candidate::new(start, end, cue.label, "cue", cue.name));
            }
        }
        found.extend(adjacent_candidates(text, subject)?);
        Ok(found)
    }

    // ---- shapes ----

    fn shape_candidates(&self, text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
        let mut found = Vec::new();
        found.extend(street_candidates(text, subject)?);
        for m in TITLE_STREET.find_iter(subject)? {
            found.push(Candidate::new(m.start, m.end, "FAC", "shape", "title_street"));
        }
        for m in ORG_SUFFIX_TITLE.find_iter(subject)? {
            let (a, b) = m.group(1).unwrap_or((m.start, m.end));
            if org_shape_ok(&text[a..b]) {
                found.push(Candidate::new(a, m.end, "ORG", "shape", "org_suffix"));
            }
        }
        for m in ORG_PREFIX_TITLE.find_iter(subject)? {
            let (a, b) = m.group(1).unwrap_or((m.start, m.end));
            found.push(Candidate::new(a, b, "ORG", "shape", "org_of"));
        }
        for pattern in [&*ORG_LEGAL_ANY_CASE, &*ORG_PREFIX_ANY_CASE] {
            for m in pattern.find_iter(subject)? {
                let (a, b) = m.group(1).unwrap_or((m.start, m.end));
                if org_shape_ok(&text[a..b]) {
                    found.push(Candidate::new(a, b, "ORG", "shape", "org_legal_form"));
                }
            }
        }
        found.extend(city_state_candidates(text, subject)?);
        found.extend(person_shape_candidates(text, subject)?);
        Ok(found)
    }

    // ---- gazetteer ----

    fn gazetteer_candidates(&self, text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
        let mut found = Vec::new();
        let lowered = pytext::lower_chars(text);
        let mut names: Vec<&str> = STATE_NAMES.iter().chain(COUNTRIES.iter()).chain(CITIES.iter()).copied().collect();
        names.sort_unstable();
        names.dedup();
        for name in names {
            let needle: Vec<char> = name.chars().collect();
            for (start, end) in find_bounded(&lowered, &needle, &['\'', '\u{2019}'], &[]) {
                let raw = pytext::slice(text, start, end);
                if AMBIGUOUS_PLACES.contains(&name) && !raw.first().is_some_and(|&c| pytext::is_upper(c)) {
                    continue;
                }
                if raw.first().is_some_and(|&c| pytext::is_lower(c)) && CITIES.contains(name) {
                    let before = pytext::rstrip(&lowered[..start.min(lowered.len())]);
                    let last_word = before.rsplit(|&c| c == ' ').next().unwrap_or(&[]);
                    if !BEFORE_CITY_WORDS.contains(&pytext::string(last_word).as_str()) {
                        continue;
                    }
                }
                found.push(Candidate::new(start, end, "GPE", "gazetteer", "place_list"));
            }
        }
        for m in GIVEN_PAIR.find_iter(subject)? {
            let (fa, fb) = m.group(1).unwrap_or((m.start, m.end));
            let (sa, sb) = m.group(2).unwrap_or((m.start, m.end));
            let (first, second) = (&text[fa..fb], &text[sa..sb]);
            if !GIVEN_NAMES.contains(lower(first).as_str()) || NAME_STOP.contains(lower(second).as_str()) {
                continue;
            }
            let capped = pytext::is_upper(first[0]) && pytext::is_upper(second[0]);
            if capped || SURNAMES.contains(lower(second).as_str()) {
                found.push(Candidate::new(m.start, m.end, "PERSON", "gazetteer", "given_name_pair"));
            }
        }
        Ok(found)
    }

    // ---- recurrence ----

    fn recurrence_candidates(&self, text: &[char], subject: &Subject, selected: &[Candidate]) -> Result<Vec<Candidate>, NerError> {
        let mut found = Vec::new();
        let lowered = fold(text);
        let mut needles: Vec<(Vec<char>, String)> = Vec::new();
        let mut add = |needle: Vec<char>, label: &str| {
            if !needles.iter().any(|(n, l)| *n == needle && l == label) {
                needles.push((needle, label.to_owned()));
            }
        };
        for cand in selected {
            let value = pytext::strip(pytext::slice(text, cand.start, cand.end));
            let lowered_value = pytext::lower_chars(value);
            if lowered_value.len() < 3 {
                continue;
            }
            add(lowered_value.clone(), &cand.label);
            if cand.label == "PERSON" {
                let parts: Vec<String> = pytext::split(&lowered_value)
                    .iter()
                    .map(|p| p.iter().filter(|&&c| matches!(c, 'a'..='z' | '\'' | '\u{2019}' | '-')).collect::<String>())
                    .collect();
                if parts.len() > 1 {
                    for part in [&parts[0], &parts[parts.len() - 1]] {
                        if part.chars().count() >= 3 && !NAME_STOP.contains(part.as_str()) && !COMMON_TITLE_WORDS.contains(part.as_str()) {
                            add(part.chars().collect(), "PERSON");
                        }
                    }
                }
            }
        }
        for (needle, label) in &needles {
            for (start, end) in find_bounded(&lowered, needle, &['\'', '\u{2019}', '-'], &['-']) {
                found.push(Candidate::new(start, end, label, "recurrence", "repeat_of_found"));
            }
        }
        found.extend(promoted_sequences(text, subject)?);
        Ok(found)
    }
}

fn resolve(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut ordered = candidates;
    ordered.sort_by_key(|c| (c.key(), c.start));
    let mut chosen: Vec<Candidate> = Vec::new();
    for cand in ordered {
        if cand.end <= cand.start {
            continue;
        }
        if chosen.iter().any(|o| cand.start < o.end && o.start < cand.end) {
            continue;
        }
        chosen.push(cand);
    }
    chosen.sort_by_key(|c| c.start);
    chosen
}

fn result(text: &[char], cand: &Candidate) -> Result<PatternResult, NerError> {
    let case = use_case(&cand.label).ok_or_else(|| NerError::SpacyBackend(format!("'{}'", cand.label)))?;
    Ok(PatternResult {
        label: cand.label.clone(),
        entity_type: case.entity_type,
        mechanism: cand.mechanism,
        cue: cand.cue.clone(),
        span: (cand.start, cand.end),
        text: pytext::string(pytext::slice(text, cand.start, cand.end)),
        classification: case.classification(),
        confidence: case.confidence,
        reasoning: format!("pattern detector ({}:{}) labelled this span as {}", cand.mechanism, cand.cue, cand.label),
    })
}

fn plausible_name(text: &[char], start: usize, end: usize) -> Result<bool, PatternError> {
    let value = pytext::slice(text, start, end);
    for token in pytext::split(value) {
        let stripped = lower(pytext::strip_set(token, &['.']));
        if ROLE_WORDS.contains(stripped.as_str()) || ORG_WORDS.contains(stripped.as_str()) {
            return Ok(false);
        }
    }
    let tail = pytext::slice(text, end, end + 40);
    if let Some(m) = FOLLOWING_WORD.match_at(&Subject::new(tail), 0)? {
        let (a, b) = m.group(1).unwrap_or((0, 0));
        let word = lower(&tail[a..b]);
        if ROLE_WORDS.contains(word.as_str()) || ORG_WORDS.contains(word.as_str()) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn plausible_org(value: &[char]) -> bool {
    let parts = pytext::split(value);
    let Some(first) = parts.first() else { return false };
    !ORG_LEAD_STOP.contains(lower(first).as_str()) && value.len() > 2
}

fn adjacent_candidates(text: &[char], subject: &Subject) -> Result<Vec<Candidate>, PatternError> {
    let mut found = Vec::new();
    for (pattern, cue_name, allow_lower) in ADJACENT.iter() {
        for m in pattern.find_iter(subject)? {
            let (run_start, run_end) = m.group(1).unwrap_or((m.start, m.end));
            let run = &text[run_start..run_end];
            let all_tokens = crate::postfilter::alpha_tokens(run);
            let mut tokens: Vec<(usize, usize)> = all_tokens;
            let mut words: Vec<String> = tokens.iter().map(|&(a, b)| pytext::string(&run[a..b])).collect();
            let blocked = |w: &str| {
                let l = pytext::lower(w);
                NAME_STOP.contains(l.as_str()) || COMMON_TITLE_WORDS.contains(l.as_str())
            };
            let mut lead = 0;
            while lead < words.len() && blocked(&words[lead]) {
                lead += 1;
            }
            words.drain(..lead);
            tokens.drain(..lead);
            if words.is_empty() || words.iter().any(|w| blocked(w)) {
                continue;
            }
            let first_char = |w: &String| w.chars().next();
            let capped = words.iter().all(|w| first_char(w).is_some_and(pytext::is_upper));
            let lowered = words.iter().all(|w| first_char(w).is_some_and(pytext::is_lower));
            if !(capped || (lowered && *allow_lower && words.len() >= 2)) {
                continue;
            }
            let start = run_start + tokens[0].0;
            let end = run_start + tokens[tokens.len() - 1].1;
            found.push(Candidate::new(start, end, "PERSON", "cue", cue_name));
        }
    }
    Ok(found)
}

fn org_shape_ok(value: &[char]) -> bool {
    let replaced: Vec<char> = value.iter().map(|&c| if c == ',' { ' ' } else { c }).collect();
    let tokens: Vec<String> = pytext::split(&replaced).iter().map(|t| lower(t)).collect();
    let Some(first) = tokens.first() else { return false };
    let lead: &[String] =
        if !["university", "college", "bank", "institute"].contains(&first.as_str()) { &tokens[..tokens.len() - 1] } else { &tokens[..1] };
    !lead.is_empty() && lead.iter().all(|t| !FUNCTION_WORDS.contains(t.as_str()) && !MONTHS_DAYS.contains(t.as_str()))
}

fn street_candidates(text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
    let mut found = Vec::new();
    for m in STREET.find_iter(subject)? {
        let (num_a, num_b) = m.group(1).unwrap_or((m.start, m.start));
        let (mid_a, mid_b) = m.group(2).unwrap_or((m.start, m.start));
        let (suf_a, suf_b) = m.group(3).unwrap_or((m.end, m.end));
        let mid = pytext::split(&text[mid_a..mid_b]);
        let suffix_word = lower(&text[suf_a..suf_b]);
        let Some(&(_, suffix_kind)) = ADDRESS_SUFFIX.iter().find(|(w, _)| !w.is_empty() && *w == suffix_word) else {
            return Err(NerError::SpacyBackend(format!("'{suffix_word}'")));
        };
        let lowered: Vec<String> = mid.iter().map(|t| lower(t).trim_matches('.').to_owned()).collect();
        if lowered.iter().any(|t| FUNCTION_WORDS.contains(t.as_str()) || UNIT_WORDS.contains(t.as_str())) {
            continue;
        }
        let mut has_tail = false;
        if let Some(tail) = STREET_TAIL.match_at(subject, m.end)?
            && let Some(place) = scan_value(text, subject, tail.end, Scan::Place, 3, true, true)?
        {
            let region_end = extend_region(subject, place.1)?;
            has_tail = true;
            found.push(Candidate::new(place.0, region_end, "GPE", "shape", "street_city"));
        }
        let all_cap = mid.iter().all(|t| t.first().is_some_and(|&c| pytext::is_upper(c)));
        if suffix_kind == "amb" && !(has_tail || (all_cap && num_b - num_a >= 2)) {
            continue;
        }
        if mid.is_empty() || mid[0].is_empty() {
            continue;
        }
        found.push(Candidate::new(num_a, m.end, "FAC", "shape", "street_address"));
    }
    Ok(found)
}

fn city_state_candidates(text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
    let mut found = Vec::new();
    for m in CITY.find_iter(subject)? {
        let (a, b) = m.group(1).unwrap_or((m.start, m.end));
        let end = extend_region(subject, b)?;
        if end > b {
            if pytext::split(&text[a..b]).iter().any(|t| PLACE_STOP.contains(lower(t).as_str())) {
                continue;
            }
            found.push(Candidate::new(a, end, "GPE", "shape", "city_state"));
        }
    }
    for m in LOWER_CITY.find_iter(subject)? {
        let (a, b) = m.group(1).unwrap_or((m.start, m.end));
        let mut tokens: Vec<&[char]> = pytext::split(&text[a..b]);
        while tokens.first().is_some_and(|t| PLACE_STOP.contains(pytext::string(t).as_str())) {
            tokens.remove(0);
        }
        let Some(first) = tokens.first() else { continue };
        // text.rfind(tokens[0], m.start(1), m.end(1))
        let window = &text[a..b];
        let start = (0..=window.len().saturating_sub(first.len())).rev().find(|&i| window[i..].starts_with(first)).map_or(a, |i| a + i);
        let end = extend_region(subject, b)?;
        found.push(Candidate::new(start, end, "GPE", "shape", "city_state_zip"));
    }
    Ok(found)
}

fn person_shape_candidates(text: &[char], subject: &Subject) -> Result<Vec<Candidate>, NerError> {
    let mut found = Vec::new();
    for m in TITLE_RUN.find_iter(subject)? {
        let (run_a, run_b) = m.group(1).unwrap_or((m.start, m.end));
        let run = &text[run_a..run_b];
        let tokens = pytext::split_ranges(run);
        let mut words: Vec<String> = tokens.iter().map(|&(a, b)| pytext::string(&run[a..b])).collect();
        let mut lowered: Vec<String> = words.iter().map(|w| letters_a_z(w)).collect();
        let last_index = words.len() - 1;
        let (last, _) = strip_possessive(&words[last_index]);
        let span_end = run_a + tokens[last_index].0 + last.chars().count();
        lowered[last_index] = letters_a_z(&last);
        words[last_index] = last;
        let blocked = |w: &str| NAME_STOP.contains(w) || COMMON_TITLE_WORDS.contains(w);
        let (mut lead, mut tail) = (0, words.len());
        while lead < tail && blocked(&lowered[lead]) {
            lead += 1;
        }
        while tail > lead && blocked(&lowered[tail - 1]) {
            tail -= 1;
        }
        if tail - lead < 2 {
            continue;
        }
        if lowered[lead..tail]
            .iter()
            .any(|t| blocked(t) || COUNTRIES.contains(t.as_str()) || STATE_NAMES.contains(t.as_str()) || CITIES.contains(t.as_str()))
        {
            continue;
        }
        let start = run_a + tokens[lead].0;
        let end = if tail == words.len() { span_end } else { run_a + tokens[tail - 1].1 };
        if sentence_start(text, start)? {
            let after = pytext::slice(text, end, end + 60);
            if TITLE_RECORD_TAIL.match_at(&Subject::new(after), 0)?.is_none() {
                continue;
            }
            found.push(Candidate::new(start, end, "PERSON", "shape", "title_record"));
            continue;
        }
        found.push(Candidate::new(start, end, "PERSON", "shape", "title_sequence"));
    }
    Ok(found)
}

fn promoted_sequences(text: &[char], subject: &Subject) -> Result<Vec<Candidate>, PatternError> {
    let mut order: Vec<String> = Vec::new();
    let mut occurrences: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
    for m in TITLE_RUN.find_iter(subject)? {
        let (run_a, run_b) = m.group(1).unwrap_or((m.start, m.end));
        let run = &text[run_a..run_b];
        let mut words: Vec<String> = pytext::split(run).iter().map(|w| pytext::string(w)).collect();
        let last_index = words.len() - 1;
        let original_last_len = words[last_index].chars().count();
        let (last, _) = strip_possessive(&words[last_index]);
        let last_len = last.chars().count();
        words[last_index] = last;
        let lowered: Vec<String> = words.iter().map(|w| letters_a_z(w)).collect();
        if lowered.iter().any(|t| {
            NAME_STOP.contains(t.as_str())
                || COMMON_TITLE_WORDS.contains(t.as_str())
                || COUNTRIES.contains(t.as_str())
                || STATE_NAMES.contains(t.as_str())
                || CITIES.contains(t.as_str())
        }) {
            continue;
        }
        let end = run_a + run.len() - (original_last_len - last_len);
        let key = words.join(" ");
        if !occurrences.contains_key(&key) {
            order.push(key.clone());
        }
        occurrences.entry(key).or_default().push((run_a, end));
    }
    let mut found = Vec::new();
    for key in order {
        if let Some(hits) = occurrences.get(&key).filter(|hits| hits.len() >= 2) {
            for &(start, end) in hits {
                found.push(Candidate::new(start, end, "PERSON", "recurrence", "promoted_sequence"));
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn cue_names(text: &str, options: PatternOptions) -> Vec<(usize, usize, String)> {
        PatternEntityDetector::new(options)
            .extract_entities(text)
            .expect("runs")
            .into_iter()
            .filter_map(|o| match o {
                PatternOutput::Found(r) => Some((r.span.0, r.span.1, r.cue)),
                PatternOutput::Seed(_) => None,
            })
            .collect()
    }

    const CUES_ONLY: PatternOptions = PatternOptions { use_cues: true, use_shape: false, use_recurrence: false, use_gazetteer: false };

    #[test]
    fn the_accented_relation_matches_like_the_unaccented_one() {
        let plain = cue_names("my fiancee Zoe lives here", CUES_ONLY);
        let accented = cue_names("my fianc\u{e9}e Zoe lives here", CUES_ONLY);
        let upper = cue_names("my FIANC\u{c9}E Zoe lives here", CUES_ONLY);
        assert_eq!(plain, vec![(11, 14, "relation_apposition".to_owned())]);
        assert_eq!(accented, plain);
        assert_eq!(upper, plain);
        assert!(cue_names("my fianc\u{e8}e Zoe lives here", CUES_ONLY).is_empty());
    }

    #[test]
    fn a_street_address_and_its_city_are_shapes() {
        let found = cue_names(
            "Send it to 12 Oak Street, Springfield, IL 62704 please.",
            PatternOptions { use_cues: false, use_shape: true, ..CUES_ONLY },
        );
        assert!(found.iter().any(|(_, _, cue)| cue == "street_address"));
        assert!(found.iter().any(|(_, _, cue)| cue == "street_city" || cue == "city_state"));
    }
}
