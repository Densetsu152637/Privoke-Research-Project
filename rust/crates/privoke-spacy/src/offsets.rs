//! Offset conversion. spaCy reports character offsets in Python code points. Rust strings are UTF-8, and the
//! extension boundary uses UTF-16 code units, matching today's behaviour (a JavaScript string index).

/// Code-point to UTF-8 byte and UTF-16 code-unit offsets for one text.
#[derive(Clone, Debug)]
pub struct OffsetMap {
    byte: Vec<usize>,
    utf16: Vec<usize>,
}

impl OffsetMap {
    /// Builds the tables in one pass. Both have `chars + 1` entries, so the end offset of a span that reaches the end
    /// of the text converts too.
    pub fn new(text: &str) -> Self {
        let mut byte = Vec::with_capacity(text.len() + 1);
        let mut utf16 = Vec::with_capacity(text.len() + 1);
        let mut units = 0;
        for (b, c) in text.char_indices() {
            byte.push(b);
            utf16.push(units);
            units += c.len_utf16();
        }
        byte.push(text.len());
        utf16.push(units);
        Self { byte, utf16 }
    }

    /// The text length in code points.
    pub fn char_len(&self) -> usize {
        self.byte.len() - 1
    }

    /// The UTF-8 byte offset of a code-point offset.
    pub fn byte(&self, char_offset: usize) -> Option<usize> {
        self.byte.get(char_offset).copied()
    }

    /// The UTF-16 code-unit offset of a code-point offset.
    pub fn utf16(&self, char_offset: usize) -> Option<usize> {
        self.utf16.get(char_offset).copied()
    }

    /// Converts a code-point range into a [`Span`], or `None` when it is reversed or outside the text.
    pub fn span(&self, start_char: usize, end_char: usize) -> Option<Span> {
        if start_char > end_char {
            return None;
        }
        Some(Span {
            start_char,
            end_char,
            start_byte: self.byte(start_char)?,
            end_byte: self.byte(end_char)?,
            start_utf16: self.utf16(start_char)?,
            end_utf16: self.utf16(end_char)?,
        })
    }
}

/// A range of the analysed text in all three units.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    /// Start in Python code points (spaCy's unit).
    pub start_char: usize,
    /// End (exclusive) in code points.
    pub end_char: usize,
    /// Start as a UTF-8 byte offset, for slicing the Rust string.
    pub start_byte: usize,
    /// End (exclusive) as a UTF-8 byte offset.
    pub end_byte: usize,
    /// Start in UTF-16 code units, for the extension.
    pub start_utf16: usize,
    /// End (exclusive) in UTF-16 code units.
    pub end_utf16: usize,
}

impl Span {
    /// The byte range, for `&text[span.bytes()]`.
    pub fn bytes(&self) -> std::ops::Range<usize> {
        self.start_byte..self.end_byte
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_the_identity() {
        let map = OffsetMap::new("hello");
        assert_eq!(map.char_len(), 5);
        assert_eq!(map.span(1, 5).unwrap().bytes(), 1..5);
        assert_eq!(map.utf16(5), Some(5));
        assert_eq!(map.span(6, 6), None);
        assert_eq!(map.span(3, 2), None);
    }

    #[test]
    fn astral_emoji_is_one_code_point_four_bytes_two_units() {
        let text = "a\u{1F600}b";
        let map = OffsetMap::new(text);
        assert_eq!(map.char_len(), 3);
        let span = map.span(1, 2).unwrap();
        assert_eq!((span.start_byte, span.end_byte), (1, 5));
        assert_eq!((span.start_utf16, span.end_utf16), (1, 3));
        assert_eq!(&text[span.bytes()], "\u{1F600}");
        assert_eq!(map.utf16(3), Some(4));
    }

    #[test]
    fn combining_marks_count_as_separate_code_points() {
        // "e" + COMBINING ACUTE ACCENT: two code points, 1 + 2 bytes, 2 units.
        let text = "e\u{0301}x";
        let map = OffsetMap::new(text);
        assert_eq!(map.char_len(), 3);
        assert_eq!(map.byte(1), Some(1));
        assert_eq!(map.byte(2), Some(3));
        assert_eq!(map.utf16(2), Some(2));
    }

    #[test]
    fn cjk_is_three_bytes_one_unit() {
        let text = "\u{6771}\u{4EAC}\u{90FD}";
        let map = OffsetMap::new(text);
        let span = map.span(1, 3).unwrap();
        assert_eq!((span.start_byte, span.end_byte), (3, 9));
        assert_eq!((span.start_utf16, span.end_utf16), (1, 3));
        assert_eq!(&text[span.bytes()], "\u{4EAC}\u{90FD}");
    }

    #[test]
    fn empty_text_has_one_boundary() {
        let map = OffsetMap::new("");
        assert_eq!(map.char_len(), 0);
        assert_eq!(map.span(0, 0).unwrap().bytes(), 0..0);
        assert_eq!(map.byte(1), None);
    }
}
