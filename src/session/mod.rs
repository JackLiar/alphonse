use super::packet;

/// network session
pub struct Session {
    pub id: String,
    /// Some session only contains one direction's packets
    /// Some protocols may work in that way
    /// but network problems could cause single direction
    pub single_direction: bool,
    /// session total bytes
    pub bytes: [u64; 2],
    /// session total data bytes
    pub data_bytes: [u64; 2],
    /// session start time
    pub start_time: libc::timeval,
    /// session end time
    pub end_time: libc::timeval,
    /// session's packets
    pub pkts: Vec<Box<packet::Packet>>,
    /// indicate nothing to parse here
    pub parse_finished: bool,
}

impl Session {
    /// Create a new session
    pub fn new() -> Session {
        Session {
            id: String::new(),
            single_direction: false,
            bytes: [0; 2],
            data_bytes: [0; 2],
            start_time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            end_time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            pkts: Vec::new(),
            parse_finished: false,
        }
    }
}
