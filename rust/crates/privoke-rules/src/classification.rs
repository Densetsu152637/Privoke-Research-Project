//! The packed classification word of `privoke_contracts.classification`.

/// Sensitivity levels (the low two bits).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Sensitivity {
    /// No sensitivity.
    S0 = 0,
    /// Low.
    S1 = 1,
    /// Medium.
    S2 = 2,
    /// High.
    S3 = 3,
}

/// Visibility values (three bits above sensitivity).
pub mod visibility {
    /// Public.
    pub const P0: u16 = 0b00100;
    /// Semi-public.
    pub const P1: u16 = 0b01000;
    /// Restricted.
    pub const P2: u16 = 0b01100;
    /// Group private.
    pub const P3: u16 = 0b10000;
    /// Personal private.
    pub const P4: u16 = 0b10100;
    /// Unknown, the default.
    pub const PU: u16 = 0b11100;
}

/// Category bits.
pub mod category {
    /// Health.
    pub const HEALTH: u16 = 0b000_0000_0010_0000;
    /// Politics.
    pub const POLITICS: u16 = 0b000_0000_0100_0000;
    /// Religion.
    pub const RELIGION: u16 = 0b000_0000_1000_0000;
    /// Criminal.
    pub const CRIMINAL: u16 = 0b000_0001_0000_0000;
    /// Financial.
    pub const FINANCIAL: u16 = 0b000_0010_0000_0000;
    /// Sexual.
    pub const SEXUAL: u16 = 0b000_0100_0000_0000;
    /// Child.
    pub const CHILD: u16 = 0b000_1000_0000_0000;
    /// Location.
    pub const LOCATION: u16 = 0b001_0000_0000_0000;
    /// Identity.
    pub const IDENTITY: u16 = 0b010_0000_0000_0000;
    /// Third party.
    pub const THIRD_PARTY: u16 = 0b100_0000_0000_0000;
}

const SENSITIVITY_MASK: u16 = 0b00011;
const CATEGORY_MASK: u16 = 0x7FE0;
const CLASSIFICATION_MASK: u16 = 0xFFFF;

/// A packed classification: sensitivity, visibility and category bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Classification(u16);

impl Classification {
    /// `initialise_unpacked(sensitivity, visibility, categories)` with the categories already
    /// combined into a bit mask.
    pub const fn new(sensitivity: Sensitivity, visibility: u16, categories: u16) -> Self {
        Self((sensitivity as u16 | visibility | categories) & CLASSIFICATION_MASK)
    }

    /// The packed word.
    pub const fn pack(self) -> u16 {
        self.0
    }

    /// The sensitivity.
    pub const fn sensitivity(self) -> Sensitivity {
        match self.0 & SENSITIVITY_MASK {
            0 => Sensitivity::S0,
            1 => Sensitivity::S1,
            2 => Sensitivity::S2,
            _ => Sensitivity::S3,
        }
    }

    /// The category bit mask.
    pub const fn categories(self) -> u16 {
        self.0 & CATEGORY_MASK
    }
}
