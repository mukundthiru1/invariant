#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

#[cfg_attr(feature = "wasm", wasm_bindgen)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZeroTrustTier {
    Unknown = 0,
    Monitored = 1,
    Suspicious = 2,
    Hostile = 3,
    Blocked = 4,
}

impl ZeroTrustTier {
    pub fn from_threat_level(threat_level: f64) -> Self {
        if threat_level < 0.2 {
            Self::Unknown
        } else if threat_level < 0.45 {
            Self::Monitored
        } else if threat_level < 0.65 {
            Self::Suspicious
        } else if threat_level < 0.85 {
            Self::Hostile
        } else {
            Self::Blocked
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Monitored => "Monitored",
            Self::Suspicious => "Suspicious",
            Self::Hostile => "Hostile",
            Self::Blocked => "Blocked",
        }
    }

    pub fn numeric_value(&self) -> u8 {
        *self as u8
    }
}

pub fn classify_session(signals: &[f64]) -> ZeroTrustTier {
    if signals.is_empty() {
        return ZeroTrustTier::Unknown;
    }

    let avg = signals.iter().sum::<f64>() / signals.len() as f64;
    ZeroTrustTier::from_threat_level(avg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_threat_level_0_0_is_unknown() {
        assert_eq!(ZeroTrustTier::from_threat_level(0.0), ZeroTrustTier::Unknown);
    }

    #[test]
    fn from_threat_level_0_1_is_unknown() {
        assert_eq!(ZeroTrustTier::from_threat_level(0.1), ZeroTrustTier::Unknown);
    }

    #[test]
    fn from_threat_level_0_2_is_monitored() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.2),
            ZeroTrustTier::Monitored
        );
    }

    #[test]
    fn from_threat_level_0_44_is_monitored() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.44),
            ZeroTrustTier::Monitored
        );
    }

    #[test]
    fn from_threat_level_0_45_is_suspicious() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.45),
            ZeroTrustTier::Suspicious
        );
    }

    #[test]
    fn from_threat_level_0_64_is_suspicious() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.64),
            ZeroTrustTier::Suspicious
        );
    }

    #[test]
    fn from_threat_level_0_65_is_hostile() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.65),
            ZeroTrustTier::Hostile
        );
    }

    #[test]
    fn from_threat_level_0_84_is_hostile() {
        assert_eq!(
            ZeroTrustTier::from_threat_level(0.84),
            ZeroTrustTier::Hostile
        );
    }

    #[test]
    fn from_threat_level_0_85_is_blocked() {
        assert_eq!(ZeroTrustTier::from_threat_level(0.85), ZeroTrustTier::Blocked);
    }

    #[test]
    fn from_threat_level_1_0_is_blocked() {
        assert_eq!(ZeroTrustTier::from_threat_level(1.0), ZeroTrustTier::Blocked);
    }
}
