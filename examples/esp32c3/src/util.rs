use esp_hal::time::{Duration, Instant};

pub fn do_something() -> ! {
    loop {
        let delay_start = Instant::now();
        while delay_start.elapsed() < Duration::from_secs(1) {}
    }
}
