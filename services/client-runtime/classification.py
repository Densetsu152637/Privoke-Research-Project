
from enum import Enum
from typing import List

class Sensitivity(Enum):

    S0 = 0b00 # None / Benign
    S1 = 0b01 # Low: mild personal opinions, non-identifying
    S2 = 0b10 # Medium: personal information that could cause targeting / harm
    S3 = 0b11 # High: explicit sensitive categories + identifiable details

class Visibility(Enum):

    P0 = 0b00100 # Public: visible to anyone
    P1 = 0b01000 # Semi-public: public but context limited (community page / thread)
    P2 = 0b01100 # Restricted: behind authentication
    P3 = 0b10000 # Private: private group chats / DMs
    PU = 0b10100 # Unknown: cannot verify from stored metadata

class Category(Enum):

    # PDPA-sensitive
    HEALTH      = 0b0000000001000000 # physical / mental condition
    POLITICS    = 0b0000000010000000
    RELIGION    = 0b0000000100000000
    CRIMINAL    = 0b0000001000000000
    # Harm-sensitive
    FINANCIAL   = 0b0000010000000000 # bank acct, debts, salary, scams
    SEXUAL      = 0b0000100000000000
    CHILD       = 0b0001000000000000
    LOCATION    = 0b0010000000000000 # exact address, “alone tonight”, routes
    IDENTITY    = 0b0100000000000000 # passport, ID numbers, phone, email
    THIRD_PARTY = 0b1000000000000000 # talking about someone else’s sensitive info

class Classification:

    s: Sensitivity
    v: Visibility
    c: List[Category]

    def __init__(self):
        pass

    def sensitivity(self) -> Sensitivity:
        return self.s

    def visibility(self) -> Visibility:
        return self.v

    def categories(self) -> List[Category]:
        return self.c

    def pack(self) -> int:
        return compact_sensitivity(self.s) | compact_visibility(self.v) | compact_categories(self.c)

# Extract sensitivity using mask (lowest 2 bits)
# Extract visibility using mask  (3-5 bits)
# Extract category using mask    (upper 10 bits)
s_mask = 0b00011
v_mask = 0b11100
c_mask = 0b111111111000000
n_mask = 0xFF

def compact_sensitivity(s: Sensitivity) -> int:
    return s.value

def compact_visibility(v: Visibility) -> int:
    return v.value

def compact_category(c: Category) -> int:
    return c.value

def compact_categories(c: List[Category]) -> int:
    return c.value

def extract_sensitivity(n: int) -> Sensitivity:
    global s_mask
    return Sensitivity(n & s_mask)

def extract_visibility(n: int) -> Visibility:
    global v_mask
    return Visibility(n & v_mask)

def extract_categories(n: int) -> List[Category]:
    global c_mask
    unmasked = n & c_mask
    return [cat for cat in Category if (unmasked & cat.value)]

def initialise_packed(n: int) -> Classification:
    global n_mask
    n = n & n_mask
    cl = Classification()
    cl.s = extract_sensitivity(n)
    cl.v = extract_visibility(n)
    cl.c = extract_categories(n)
    return cl

def initialise_unpacked(s: Sensitivity, v: Visibility, c: List[Category]) -> Classification:
    cl = Classification()
    cl.s = s
    cl.v = v
    cl.c = c
    return cl