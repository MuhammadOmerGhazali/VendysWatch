use tokio::sync::mpsc::Receiver;
use egui::{CtxRef, CentralPanel};

pub struct MonitorApp {
    pub events: Vec<String>,
    pub receiver: Receiver<String>,
}

impl eframe::App for MonitorApp {
    fn update(&mut self, ctx: &CtxRef, _frame: &mut eframe::Frame) {
        while let Ok(event) = self.receiver.try_recv() {
            self.events.push(event);
        }

        CentralPanel::default().show(ctx, |ui| {
            ui.heading("📂 File Integrity Monitoring");

            if self.events.is_empty() {
                ui.label("No events yet...");
            } else {
                for event in &self.events {
                    ui.label(event);
                }
            }
        });

        ctx.request_repaint();
    }
}
