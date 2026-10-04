//! System tray via the StatusNotifierItem spec (ksni). No GTK dependency.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::state::Shared;

pub struct ShieldTray {
    pub shared: Arc<Shared>,
}

impl ksni::Tray for ShieldTray {
    fn id(&self) -> String {
        "shield".into()
    }

    fn title(&self) -> String {
        "Shield".into()
    }

    fn icon_name(&self) -> String {
        if self.shared.has_alert.load(Ordering::SeqCst) {
            "dialog-warning".into()
        } else {
            "security-high".into()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::*;
        vec![
            StandardItem {
                label: "Show Shield".into(),
                icon_name: "window-new".into(),
                activate: Box::new(|this: &mut Self| {
                    this.shared.show.store(true, Ordering::SeqCst);
                    this.shared.has_alert.store(false, Ordering::SeqCst);
                }),
                ..Default::default()
            }
            .into(),
            StandardItem {
                label: "Baseline now".into(),
                activate: Box::new(|this: &mut Self| {
                    this.shared.baseline_requested.store(true, Ordering::SeqCst);
                }),
                ..Default::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Quit".into(),
                icon_name: "application-exit".into(),
                activate: Box::new(|this: &mut Self| {
                    this.shared.quit.store(true, Ordering::SeqCst);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}
