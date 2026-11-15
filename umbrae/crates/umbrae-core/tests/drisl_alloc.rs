//! Decoding hostile DRISL never reserves memory out of proportion to the
//! input. Its own test binary, since it swaps the global allocator to
//! record the largest single request.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use umbrae_core::drisl;

struct Largest;

static LARGEST: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Largest {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LARGEST.fetch_max(layout.size(), Ordering::Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LARGEST.fetch_max(new_size, Ordering::Relaxed);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static GLOBAL: Largest = Largest;

#[test]
fn nested_array_lengths_do_not_add_up() {
    // 100 nested arrays, each claiming every byte left after its header,
    // then filler that fails on the first item read.
    const LEVELS: usize = 100;
    const TOTAL: usize = 1024 * 1024 - 1;
    let mut input = Vec::with_capacity(TOTAL);
    for level in 0..LEVELS {
        let remaining = TOTAL - (level + 1) * 5;
        input.push(0x9a);
        input.extend_from_slice(&(remaining as u32).to_be_bytes());
    }
    input.resize(TOTAL, 0xff);
    let input_size = input.len();

    LARGEST.store(0, Ordering::Relaxed);
    assert!(drisl::decode(&input).is_err());
    let largest = LARGEST.load(Ordering::Relaxed);
    // Before the cap, each level reserved about a megabyte of slots.
    assert!(
        largest < input_size,
        "largest allocation {largest} bytes for {input_size} bytes of input"
    );
}
