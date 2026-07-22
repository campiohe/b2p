//! Frozen 256-word list for the human code (`<channel>-<word>-<word>`).
//! FROZEN: reordering or replacing any word is a breaking change to every
//! previously-shared code. Do not regenerate.

pub const WORDS: [&str; 256] = [
    "acid", "actor", "album", "alert", "alloy", "angle", "apple", "apron", "arena", "arrow",
    "atlas", "atoll", "autumn", "bacon", "bagel", "baker", "banjo", "basil", "baton", "beacon",
    "beard", "berry", "blaze", "bloom", "blush", "bonus", "bough", "brain", "brass", "brick",
    "broom", "bugle", "cabin", "cacao", "candy", "canyon", "cargo", "carol", "chalk", "cheek",
    "chime", "chirp", "chord", "cigar", "clamp", "cliff", "clove", "coast", "cocoa", "comet",
    "cough", "crane", "creek", "crisp", "crown", "curry", "delta", "depot", "diary", "dingo",
    "diver", "dodge", "donor", "dozen", "drama", "drone", "dwarf", "easel", "elbow", "elite",
    "emu", "enter", "epoch", "essay", "evict", "extra", "fancy", "felt", "ferry", "fiber", "flair",
    "flask", "flint", "flora", "flute", "forge", "fossil", "fudge", "gable", "gauge", "genie",
    "giant", "glass", "glove", "gnome", "grasp", "gravy", "grove", "gully", "habit", "haiku",
    "harp", "hatch", "heron", "hippo", "hobby", "hound", "icing", "image", "index", "ivory",
    "jazz", "jetty", "jewel", "joker", "joust", "juice", "kayak", "kelp", "kiosk", "knack",
    "label", "lance", "latch", "layer", "lever", "lilac", "llama", "lodge", "lunar", "lyric",
    "magma", "maple", "mason", "match", "melon", "mesa", "mimic", "mocha", "modem", "moose",
    "motor", "mound", "mural", "nadir", "nerve", "noble", "noise", "north", "nova", "nudge",
    "nurse", "ocean", "olive", "opal", "organ", "otter", "ozone", "panda", "paper", "parka",
    "patio", "pecan", "peony", "perch", "piano", "pilot", "pixel", "pizza", "plum", "polar",
    "porch", "proud", "prune", "punch", "puree", "quartz", "quest", "quirk", "rally", "rapid",
    "raven", "relic", "resin", "rhino", "ridge", "rival", "robot", "rouge", "ruler", "rumor",
    "salad", "salvo", "scarf", "scone", "scrap", "shale", "shelf", "shine", "siren", "skate",
    "slate", "slope", "snail", "sonar", "spice", "spore", "sprig", "stage", "steam", "stork",
    "storm", "strap", "study", "sumo", "swirl", "tabby", "talon", "taper", "tapir", "tenor",
    "thumb", "tiger", "topaz", "torch", "tower", "trace", "trend", "tribe", "truce", "tundra",
    "tweed", "twine", "umber", "unzip", "vague", "valet", "vapor", "velvet", "vigor", "vinyl",
    "viola", "vista", "vocal", "vowel", "wafer", "waltz", "wheat", "width", "wince", "woven",
    "xenon", "yodel", "yolk", "zebra", "zonal",
];

pub fn word(index: u8) -> &'static str {
    WORDS[index as usize]
}

pub fn index_of(w: &str) -> Option<u8> {
    WORDS.iter().position(|x| *x == w).map(|i| i as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_256_distinct_lowercase() {
        assert_eq!(WORDS.len(), 256);
        let mut seen = std::collections::HashSet::new();
        for w in WORDS {
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "{w} not lowercase ascii"
            );
            assert!((3..=7).contains(&w.len()), "{w} wrong length");
            assert!(seen.insert(w), "duplicate word {w}");
        }
    }

    #[test]
    fn word_index_round_trip() {
        for i in 0u8..=255 {
            assert_eq!(index_of(word(i)), Some(i));
        }
        assert_eq!(index_of("definitely-not-a-word"), None);
    }
}
