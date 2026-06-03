/// Forward distance in the u128 ring: how far `new` is ahead of `last`.
pub fn forward_distance(last: u128, new: u128) -> u128 {
    new.wrapping_sub(last)
}

/// Accept if this is the first message from the sender in the chat, or if `new`
/// is strictly ahead of `last` by at most `max_spread` (modulo 2^128).
pub fn accept_forward_seq(last: Option<u128>, new: u128, max_spread: u128) -> bool {
    match last {
        None => true,
        Some(last) => {
            let d = forward_distance(last, new);
            new > last || (d != 0 && d <= max_spread)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_message_always_accepted() {
        assert!(accept_forward_seq(None, 1, 10));
        assert!(accept_forward_seq(None, u128::MAX, 10));
    }

    #[test]
    fn accepts_forward_within_spread() {
        assert!(accept_forward_seq(Some(10), 11, 100));
        assert!(accept_forward_seq(Some(10), 110, 100));
        assert!(!accept_forward_seq(Some(10), 111, 100));
    }

    #[test]
    fn rejects_replay_and_equal() {
        assert!(!accept_forward_seq(Some(10), 10, 100));
        assert!(!accept_forward_seq(Some(10), 5, 100));
    }

    #[test]
    fn wrap_around() {
        let last = u128::MAX - 5;
        assert!(accept_forward_seq(Some(last), 3, 10));
        assert_eq!(forward_distance(last, 3), 9);
    }

    #[test]
    fn zero_spread_rejects_all_forward() {
        assert!(!accept_forward_seq(Some(1), 2, 0));
    }
}
