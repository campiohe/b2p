use indicatif::{ProgressBar, ProgressStyle};

pub fn transfer_bar(total_bytes: u64) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(
        ProgressStyle::with_template(
            "{bar:40.cyan/blue} {bytes}/{total_bytes} ({bytes_per_sec}, ETA {eta})",
        )
        .expect("valid template"),
    );
    pb
}
