//! Pure aggregation layer. No I/O, no kernel — fully unit-tested.

use procscope_common::{Event, EventKind};
use std::collections::{HashMap, VecDeque};

const N_CATEGORIES: usize = 4;
const RECENT_CAP: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    File = 0,
    Network = 1,
    Process = 2,
    Other = 3,
}

pub fn category(kind: EventKind) -> Category {
    match kind {
        EventKind::Open | EventKind::Read | EventKind::Write => Category::File,
        EventKind::Connect | EventKind::Accept => Category::Network,
        EventKind::Exec | EventKind::Exit => Category::Process,
        EventKind::Other => Category::Other,
    }
}

#[derive(Clone, Debug, Default)]
pub struct Process {
    pub pid: u32,
    pub total: u64,
    pub by_category: [u64; N_CATEGORIES],
    pub recent: VecDeque<Event>,
}

#[derive(Default)]
pub struct AppState {
    procs: HashMap<u32, Process>,
    dropped: u64,
}

impl AppState {
    pub fn ingest(&mut self, e: Event) {
        let kind = kind_from_u32(e.kind);
        let entry = self.procs.entry(e.pid).or_insert_with(|| Process {
            pid: e.pid,
            ..Default::default()
        });
        entry.total += 1;
        entry.by_category[category(kind) as usize] += 1;
        entry.recent.push_back(e);
        if entry.recent.len() > RECENT_CAP {
            entry.recent.pop_front();
        }
    }

    pub fn process(&self, pid: u32) -> Option<&Process> {
        self.procs.get(&pid)
    }

    pub fn processes_by_activity(&self) -> Vec<&Process> {
        let mut v: Vec<&Process> = self.procs.values().collect();
        v.sort_by(|a, b| b.total.cmp(&a.total).then(a.pid.cmp(&b.pid)));
        v
    }

    pub fn recent_for(&self, pid: u32) -> Vec<Event> {
        self.procs
            .get(&pid)
            .map(|p| p.recent.iter().copied().collect())
            .unwrap_or_default()
    }

    pub fn note_dropped(&mut self, n: u64) {
        self.dropped += n;
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

fn kind_from_u32(v: u32) -> EventKind {
    match v {
        0 => EventKind::Open,
        1 => EventKind::Read,
        2 => EventKind::Write,
        3 => EventKind::Connect,
        4 => EventKind::Accept,
        5 => EventKind::Exec,
        6 => EventKind::Exit,
        _ => EventKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(pid: u32, kind: EventKind) -> Event {
        Event { pid, kind: kind as u32, arg: 0, ts_ns: 0 }
    }

    #[test]
    fn categories_map_correctly() {
        assert_eq!(category(EventKind::Open), Category::File);
        assert_eq!(category(EventKind::Read), Category::File);
        assert_eq!(category(EventKind::Write), Category::File);
        assert_eq!(category(EventKind::Connect), Category::Network);
        assert_eq!(category(EventKind::Accept), Category::Network);
        assert_eq!(category(EventKind::Exec), Category::Process);
        assert_eq!(category(EventKind::Exit), Category::Process);
        assert_eq!(category(EventKind::Other), Category::Other);
    }

    #[test]
    fn aggregates_counts_per_pid() {
        let mut state = AppState::default();
        state.ingest(ev(10, EventKind::Open));
        state.ingest(ev(10, EventKind::Open));
        state.ingest(ev(10, EventKind::Connect));
        state.ingest(ev(20, EventKind::Write));

        let p10 = state.process(10).expect("pid 10 tracked");
        assert_eq!(p10.total, 3);
        assert_eq!(p10.by_category[Category::File as usize], 2);
        assert_eq!(p10.by_category[Category::Network as usize], 1);

        let p20 = state.process(20).expect("pid 20 tracked");
        assert_eq!(p20.total, 1);
    }

    #[test]
    fn processes_sorted_by_rate_desc() {
        let mut state = AppState::default();
        state.ingest(ev(1, EventKind::Open));
        state.ingest(ev(2, EventKind::Open));
        state.ingest(ev(2, EventKind::Open));
        let order: Vec<u32> = state.processes_by_activity().iter().map(|p| p.pid).collect();
        assert_eq!(order, vec![2, 1]);
    }

    #[test]
    fn keeps_bounded_recent_events_per_selected_pid() {
        let mut state = AppState::default();
        for i in 0..150u64 {
            state.ingest(Event { pid: 5, kind: EventKind::Open as u32, arg: i, ts_ns: i });
        }
        let recent = state.recent_for(5);
        assert_eq!(recent.len(), 100, "ring capped at 100");
        assert_eq!(recent.last().unwrap().arg, 149, "newest kept");
        assert_eq!(recent.first().unwrap().arg, 50, "oldest dropped");
    }

    #[test]
    fn counts_dropped_events() {
        let mut state = AppState::default();
        state.note_dropped(7);
        state.note_dropped(3);
        assert_eq!(state.dropped(), 10);
    }
}
