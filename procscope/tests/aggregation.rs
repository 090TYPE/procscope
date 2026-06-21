use procscope::model::{AppState, Category};
use procscope_common::{Event, EventKind};

fn ev(pid: u32, kind: EventKind) -> Event {
    Event { pid, kind: kind as u32, arg: 0, ts_ns: 0 }
}

#[test]
fn known_workload_produces_expected_counts() {
    let mut state = AppState::default();
    // Simulate a process that opens 3 files and makes 2 connections.
    for _ in 0..3 {
        state.ingest(ev(4242, EventKind::Open));
    }
    for _ in 0..2 {
        state.ingest(ev(4242, EventKind::Connect));
    }
    let p = state.process(4242).expect("tracked");
    assert_eq!(p.total, 5);
    assert_eq!(p.by_category[Category::File as usize], 3);
    assert_eq!(p.by_category[Category::Network as usize], 2);
}
