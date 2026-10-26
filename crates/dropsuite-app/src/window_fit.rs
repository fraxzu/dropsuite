//! Startup window geometry: make sure the main window fits the display it opens on.
//!
//! The window-state plugin restores the saved size even when it no longer fits (another display,
//! another scale factor), and the default 1440x900 logical size does not fit every display: at
//! 150 % scaling a 1920x1080 screen has a 1280x672 logical work area. A window larger than the
//! work area opens with its right edge, window controls included, off the screen.
//!
//! Everything here is in physical pixels: the window-state file, the window's outer position
//! and size, and each monitor's work area (the monitor minus the taskbar) all use them, so
//! displays with different scale factors compare correctly without conversion.

/// A rectangle in physical pixels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: u32,
    pub h: u32,
}

/// One monitor's work area and its scale factor.
#[derive(Clone, Copy, Debug)]
pub struct WorkArea {
    pub rect: Rect,
    pub scale: f64,
}

/// What to do with the window at startup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fix {
    /// It fits and its title bar is reachable: keep it as restored.
    Keep,
    /// It fits, but its title bar is not reachable: move it to this position.
    Move { x: i32, y: i32 },
    /// It is larger than the work area: give it this normal size and position (so restoring it
    /// from maximized later gives a usable window), then maximize it.
    Maximize { normal: Rect },
}

/// How far inside the title bar's corners a point must be on screen, in logical pixels.
const GRIP: f64 = 16.0;

fn contains(a: &Rect, x: i64, y: i64) -> bool {
    x >= a.x as i64 && x < a.x as i64 + a.w as i64 && y >= a.y as i64 && y < a.y as i64 + a.h as i64
}

fn overlap(a: &Rect, b: &Rect) -> i64 {
    let w = (a.x as i64 + a.w as i64).min(b.x as i64 + b.w as i64) - (a.x as i64).max(b.x as i64);
    let h = (a.y as i64 + a.h as i64).min(b.y as i64 + b.h as i64) - (a.y as i64).max(b.y as i64);
    w.max(0) * h.max(0)
}

fn clamp(v: i32, lo: i32, hi: i32) -> i32 {
    v.max(lo).min(hi.max(lo))
}

/// Decide how to fix a restored window. `areas` lists the monitors' work areas, primary first.
/// The window is measured against the work area it overlaps most, or the primary one when it
/// overlaps none.
pub fn plan(window: Rect, maximized_or_fullscreen: bool, areas: &[WorkArea]) -> Fix {
    if maximized_or_fullscreen || areas.is_empty() {
        return Fix::Keep;
    }
    let target = areas
        .iter()
        .map(|a| (overlap(&window, &a.rect), a))
        .fold(None::<(i64, &WorkArea)>, |best, (o, a)| match best {
            Some((b, _)) if b >= o => best,
            _ if o > 0 => Some((o, a)),
            _ => best,
        })
        .map_or(&areas[0], |(_, a)| a);
    let wa = target.rect;

    if window.w > wa.w || window.h > wa.h {
        let w = window.w.min(wa.w / 10 * 9);
        let h = window.h.min(wa.h / 10 * 9);
        return Fix::Maximize {
            normal: Rect {
                x: wa.x + ((wa.w - w) / 2) as i32,
                y: wa.y + ((wa.h - h) / 2) as i32,
                w,
                h,
            },
        };
    }

    // Reachable: both ends of the title bar are on some monitor's work area, so it can be
    // dragged and its window controls (top right) clicked. A window may span monitors.
    let grip = (GRIP * target.scale).round() as i64;
    let top = window.y as i64 + grip;
    let reachable = [
        window.x as i64 + grip,
        window.x as i64 + window.w as i64 - grip,
    ]
    .into_iter()
    .all(|x| areas.iter().any(|a| contains(&a.rect, x, top)));
    if reachable {
        return Fix::Keep;
    }
    Fix::Move {
        x: clamp(window.x, wa.x, wa.x + (wa.w - window.w) as i32),
        y: clamp(window.y, wa.y, wa.y + (wa.h - window.h) as i32),
    }
}

/// What the window-state plugin saves and restores: everything except decorations, so a state
/// file written by an older, decorated build cannot bring the native title bar back.
pub fn state_flags() -> tauri_plugin_window_state::StateFlags {
    tauri_plugin_window_state::StateFlags::all()
        & !tauri_plugin_window_state::StateFlags::DECORATIONS
}

/// Apply [`plan`] to the main window once, after the window-state plugin restored it. Call it
/// off the event-loop thread (see `main`): the plugin then records the corrected normal size and
/// position from the move and resize events, and the maximize after them, as it does when the
/// user maximizes a window, and saves them on exit. The next start opens with geometry that
/// already fits, so nothing is corrected again.
pub fn fit_to_work_area(window: &tauri::WebviewWindow) {
    let (Ok(pos), Ok(size)) = (window.outer_position(), window.outer_size()) else {
        return;
    };
    if window.is_fullscreen().unwrap_or(false) {
        return;
    }
    let maximized = window.is_maximized().unwrap_or(false);
    let mut monitors = window.available_monitors().unwrap_or_default();
    let primary = window.primary_monitor().ok().flatten();
    if let Some(primary) = &primary {
        // Primary first: it is the fallback for a window that is on no monitor at all.
        monitors.sort_by_key(|m| m.position() != primary.position());
    }
    let areas: Vec<WorkArea> = monitors
        .iter()
        .map(|m| {
            let r = m.work_area();
            WorkArea {
                rect: Rect {
                    x: r.position.x,
                    y: r.position.y,
                    w: r.size.width,
                    h: r.size.height,
                },
                scale: m.scale_factor(),
            }
        })
        .collect();

    if maximized {
        // A maximized window covers its work area. What can still be wrong is the normal size
        // it returns to when un-maximized, which the plugin restored from the saved state before
        // maximizing. Check that rectangle the same way; if it needs fixing, un-maximize once,
        // fix it (so the plugin records the new size and position) and maximize again.
        let Some((x, y, w, h)) = crate::platform::normal_rect(window) else {
            return;
        };
        // The normal rectangle is in workspace coordinates, which are offset from screen
        // coordinates by a taskbar at the top or left of the primary monitor.
        let (dx, dy) = primary.as_ref().map_or((0, 0), |p| {
            let wa = p.work_area();
            (
                wa.position.x - p.position().x,
                wa.position.y - p.position().y,
            )
        });
        let normal = Rect {
            x: x + dx,
            y: y + dy,
            w,
            h,
        };
        let fix = plan(normal, false, &areas);
        if fix == Fix::Keep {
            return;
        }
        tracing::info!(
            "Saved normal window {}x{} at {},{} does not fit the work area; corrected, still maximized",
            normal.w,
            normal.h,
            normal.x,
            normal.y
        );
        let _ = window.unmaximize();
        apply(window, fix);
        let _ = window.maximize();
        return;
    }

    let current = Rect {
        x: pos.x,
        y: pos.y,
        w: size.width,
        h: size.height,
    };
    let fix = plan(current, false, &areas);
    match fix {
        Fix::Keep => {}
        Fix::Move { x, y } => {
            tracing::info!(
                "Window was off screen at {},{}; moved to {x},{y}",
                current.x,
                current.y
            );
        }
        Fix::Maximize { normal } => {
            tracing::info!(
                "Window {}x{} does not fit the work area; maximized (normal size now {}x{})",
                current.w,
                current.h,
                normal.w,
                normal.h
            );
        }
    }
    apply(window, fix);
    if matches!(fix, Fix::Maximize { .. }) {
        let _ = window.maximize();
    }
}

/// Give a normal (not maximized) window the position, and for [`Fix::Maximize`] the outer size,
/// that `fix` asks for. Tauri sets the inner size, so the frame (the invisible resize border of
/// this frameless window) is subtracted to get the requested outer size.
fn apply(window: &tauri::WebviewWindow, fix: Fix) {
    use tauri::{PhysicalPosition, PhysicalSize};
    match fix {
        Fix::Keep => {}
        Fix::Move { x, y } => {
            let _ = window.set_position(PhysicalPosition::new(x, y));
        }
        Fix::Maximize { normal } => {
            let (frame_w, frame_h) = match (window.outer_size(), window.inner_size()) {
                (Ok(o), Ok(i)) => (
                    o.width.saturating_sub(i.width),
                    o.height.saturating_sub(i.height),
                ),
                _ => (0, 0),
            };
            let _ = window.set_size(PhysicalSize::new(
                normal.w.saturating_sub(frame_w).max(1),
                normal.h.saturating_sub(frame_h).max(1),
            ));
            let _ = window.set_position(PhysicalPosition::new(normal.x, normal.y));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 1920x1080 at 150 %, taskbar 48 logical px (72 physical) at the bottom: the laptop that
    /// reported the problem (logical work area 1280x672).
    const LAPTOP: WorkArea = WorkArea {
        rect: Rect {
            x: 0,
            y: 0,
            w: 1920,
            h: 1008,
        },
        scale: 1.5,
    };
    /// 1920x1080 at 100 %, taskbar 40 px.
    const DESKTOP: WorkArea = WorkArea {
        rect: Rect {
            x: 0,
            y: 0,
            w: 1920,
            h: 1040,
        },
        scale: 1.0,
    };

    fn r(x: i32, y: i32, w: u32, h: u32) -> Rect {
        Rect { x, y, w, h }
    }

    fn inside(inner: Rect, outer: Rect) -> bool {
        inner.x >= outer.x
            && inner.y >= outer.y
            && inner.x as i64 + inner.w as i64 <= outer.x as i64 + outer.w as i64
            && inner.y as i64 + inner.h as i64 <= outer.y as i64 + outer.h as i64
    }

    /// The window after a fix, as the next start would restore it.
    fn after(window: Rect, fix: Fix) -> (Rect, bool) {
        match fix {
            Fix::Keep => (window, false),
            Fix::Move { x, y } => (Rect { x, y, ..window }, false),
            Fix::Maximize { normal } => (normal, true),
        }
    }

    #[test]
    fn first_launch_default_size_that_does_not_fit_is_maximized() {
        // 1440x900 logical is 2160x1350 physical at 150 %; Windows may also clamp it to the
        // screen plus borders (observed 1946x1106 at 0,0). Neither fits 1920x1008.
        for window in [r(-120, -171, 2160, 1350), r(0, 0, 1946, 1106)] {
            match plan(window, false, &[LAPTOP]) {
                Fix::Maximize { normal } => {
                    assert!(inside(normal, LAPTOP.rect), "{normal:?}");
                    // 960x600 logical minimum still fits the normal size.
                    assert!(normal.w >= 1440 && normal.h >= 900, "{normal:?}");
                }
                other => panic!("{window:?} -> {other:?}"),
            }
        }
    }

    #[test]
    fn default_and_saved_windows_that_fit_are_kept() {
        // 1440x900 at 100 % centred on a 1920x1080 desktop: today's normal behaviour.
        assert_eq!(plan(r(240, 70, 1440, 900), false, &[DESKTOP]), Fix::Keep);
        assert_eq!(plan(r(200, 50, 1440, 900), false, &[LAPTOP]), Fix::Keep);
        // Exactly the work area still fits.
        assert_eq!(plan(r(0, 0, 1920, 1008), false, &[LAPTOP]), Fix::Keep);
    }

    #[test]
    fn saved_window_larger_than_the_work_area_is_maximized() {
        // The persisted state on the reporting laptop: 2138x1337 at -163,90.
        let fix = plan(r(-163, 90, 2138, 1337), false, &[LAPTOP]);
        assert!(
            matches!(fix, Fix::Maximize { normal } if inside(normal, LAPTOP.rect)),
            "{fix:?}"
        );
        // Too tall only: the taskbar work area counts, not the full monitor height.
        let fix = plan(r(0, 0, 1440, 1040), false, &[LAPTOP]);
        assert!(matches!(fix, Fix::Maximize { .. }), "{fix:?}");
    }

    #[test]
    fn unreachable_or_negative_positions_are_moved_on_screen() {
        for (window, want) in [
            // Left end of the title bar off screen.
            (r(-163, 90, 1440, 900), (0, 90)),
            // Right end off screen (window controls hidden).
            (r(700, 40, 1440, 900), (480, 40)),
            // Title bar above the work area.
            (r(100, -400, 1440, 900), (100, 0)),
            // Left on a monitor that is no longer connected: back to the primary.
            (r(-3000, 200, 1440, 900), (0, 108)),
            (r(5000, 5000, 1440, 900), (480, 108)),
        ] {
            assert_eq!(
                plan(window, false, &[LAPTOP]),
                Fix::Move {
                    x: want.0,
                    y: want.1
                },
                "{window:?}"
            );
        }
        // A taskbar at the top: the work area starts below it.
        let top_bar = WorkArea {
            rect: r(0, 72, 1920, 1008),
            scale: 1.5,
        };
        assert_eq!(
            plan(r(100, 0, 1440, 900), false, &[top_bar]),
            Fix::Move { x: 100, y: 72 }
        );
    }

    #[test]
    fn maximized_or_fullscreen_windows_are_left_alone() {
        // The saved normal rect may be anything; a maximized window covers the work area.
        assert_eq!(plan(r(-163, 90, 2138, 1337), true, &[LAPTOP]), Fix::Keep);
        assert_eq!(plan(r(0, 0, 1920, 1080), true, &[LAPTOP]), Fix::Keep);
        // No monitor information: do nothing rather than guess.
        assert_eq!(plan(r(-163, 90, 2138, 1337), false, &[]), Fix::Keep);
    }

    #[test]
    fn a_maximized_window_gets_a_normal_size_that_fits() {
        // The reporting laptop after maximizing by hand: maximized, but the saved normal size is
        // still 2138x1337 inner (2160x1350 outer) at -35,-22. Un-maximizing would bring it back,
        // so the normal rectangle itself is checked like a normal window.
        let fix = plan(r(-35, -22, 2160, 1350), false, &[LAPTOP]);
        assert!(
            matches!(fix, Fix::Maximize { normal } if inside(normal, LAPTOP.rect)),
            "{fix:?}"
        );
        // A maximized window whose normal rectangle fits is left as it is.
        assert_eq!(plan(r(96, 54, 1728, 900), false, &[LAPTOP]), Fix::Keep);
    }

    #[test]
    fn multiple_monitors_with_different_scales() {
        let right_4k = WorkArea {
            rect: r(1920, 0, 3840, 2100),
            scale: 2.0,
        };
        let monitors = [LAPTOP, right_4k];
        // On the second, larger monitor: a size that would not fit the laptop is fine there.
        assert_eq!(plan(r(2400, 200, 2880, 1800), false, &monitors), Fix::Keep);
        // Spanning both monitors with the title bar on screen.
        assert_eq!(plan(r(1200, 100, 1440, 900), false, &monitors), Fix::Keep);
        // Mostly on the laptop but too large for it.
        assert!(matches!(
            plan(r(-100, 0, 2000, 1000), false, &monitors),
            Fix::Maximize { normal } if inside(normal, LAPTOP.rect)
        ));
    }

    #[test]
    fn repeated_starts_do_not_oscillate() {
        let cases = [
            r(-163, 90, 2138, 1337),
            r(0, 0, 1946, 1106),
            r(-163, 90, 1440, 900),
            r(5000, 5000, 1440, 900),
            r(200, 50, 1440, 900),
        ];
        for start in cases {
            let first = plan(start, false, &[LAPTOP]);
            let (window, maximized) = after(start, first);
            // Second start: maximized stays maximized, and its saved normal rect fits too.
            assert_eq!(plan(window, maximized, &[LAPTOP]), Fix::Keep, "{start:?}");
            assert_eq!(
                plan(window, false, &[LAPTOP]),
                Fix::Keep,
                "{start:?} normal rect"
            );
        }
    }
}
