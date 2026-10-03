#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]
use eframe::egui;
use egui_extras::{Column, TableBuilder};
use std::{
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
};
use winbox_cdb::{self as cdb, Document};
use zeroize::{Zeroize, Zeroizing};

enum Event {
    Password(PathBuf),
    Loaded(PathBuf, Document),
    Failed(String),
    Exported(PathBuf),
}
struct Viewer {
    path: String,
    loaded_path: Option<PathBuf>,
    document: Option<Arc<Document>>,
    password_path: Option<PathBuf>,
    password: String,
    reveal_input: bool,
    show_passwords: bool,
    selected: Option<usize>,
    search: String,
    status: String,
    busy: bool,
    tx: mpsc::Sender<Event>,
    rx: mpsc::Receiver<Event>,
}
impl Viewer {
    fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            path: cdb::default_path().to_string_lossy().into_owned(),
            loaded_path: None,
            document: None,
            password_path: None,
            password: String::new(),
            reveal_input: false,
            show_passwords: false,
            selected: None,
            search: String::new(),
            status: "Select a WinBox address book and click Open.".into(),
            busy: false,
            tx,
            rx,
        }
    }
    fn load(&mut self, path: PathBuf, password: Option<Zeroizing<Vec<u8>>>, ctx: egui::Context) {
        self.busy = true;
        self.status = "Reading address book…".into();
        self.document = None;
        self.loaded_path = None;
        self.selected = None;
        self.search.clear();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let result = cdb::read_cdb(&path).and_then(|data| {
                if cdb::is_encrypted(&data) && password.is_none() {
                    return Ok(Event::Password(path.clone()));
                }
                cdb::decode_cdb(&data, password.as_ref().map(|p| p.as_slice()))
                    .map(|doc| Event::Loaded(path, doc))
            });
            let _ = tx.send(result.unwrap_or_else(Event::Failed));
            ctx.request_repaint();
        });
    }
    fn export(&mut self, json: bool, ctx: egui::Context) {
        let Some(doc) = self.document.clone() else {
            return;
        };
        let ext = if json { "json" } else { "txt" };
        let Some(path) = rfd::FileDialog::new()
            .set_file_name(format!("accounts.{ext}"))
            .add_filter(ext, &[ext])
            .save_file()
        else {
            return;
        };
        self.busy = true;
        self.status = "Exporting…".into();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let output = if json {
                cdb::format_json(&doc)
            } else {
                cdb::format_text(&doc)
            };
            let result = output.and_then(|text| cdb::write_private(&path, &text));
            let _ = tx.send(match result {
                Ok(()) => Event::Exported(path),
                Err(e) => Event::Failed(e),
            });
            ctx.request_repaint();
        });
    }
    fn events(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            self.busy = false;
            match event {
                Event::Password(path) => {
                    self.password_path = Some(path);
                    self.status = "This file is encrypted. Enter the address book password.".into();
                }
                Event::Loaded(path, doc) => {
                    self.status = format!("Records loaded: {}", doc.record_count);
                    self.loaded_path = Some(path);
                    self.document = Some(Arc::new(doc));
                    self.password_path = None;
                    self.password.zeroize();
                    self.reveal_input = false;
                }
                Event::Failed(error) => {
                    self.status = format!("Error: {error}");
                }
                Event::Exported(path) => {
                    self.status = format!("Export saved: {}", path.display());
                }
            }
        }
    }
}
impl Drop for Viewer {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}
impl Viewer {
    fn draw(&mut self, ui: &mut egui::Ui) {
        self.events();
        let ctx = ui.ctx().clone();
        ui.heading("WinBox · CDB Viewer");
        ui.label("Saved connections");
        ui.add_space(8.0);
        ui.add_enabled_ui(!self.busy && self.password_path.is_none(), |ui| {
            ui.horizontal(|ui| {
                ui.label("File:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .desired_width((ui.available_width() - 300.0).max(180.0)),
                );
                if ui.button("Browse…").clicked() {
                    let current = PathBuf::from(&self.path);
                    let mut dialog = rfd::FileDialog::new().add_filter("WinBox CDB", &["cdb"]);
                    if let Some(parent) = current.parent().filter(|p| p.is_dir()) {
                        dialog = dialog.set_directory(parent);
                    }
                    if let Some(path) = dialog.pick_file() {
                        self.path = path.to_string_lossy().into_owned();
                        self.load(path, None, ctx.clone());
                    }
                }
                if ui.button("Open").clicked() {
                    self.load(PathBuf::from(&self.path), None, ctx.clone());
                }
                if ui.button("WinBox path").clicked() {
                    self.path = cdb::default_path().to_string_lossy().into_owned();
                }
            });
        });
        ui.horizontal(|ui| {
            if self.busy {
                ui.spinner();
            }
            ui.label(&self.status);
        });
        if let Some(path) = self.loaded_path.as_ref() {
            ui.small(format!("Source: {}", path.display()));
        }
        ui.separator();
        ui.add_enabled_ui(self.document.is_some() && !self.busy,|ui| {
            ui.horizontal(|ui| {
                ui.label("Search:");ui.text_edit_singleline(&mut self.search);
                ui.checkbox(&mut self.show_passwords,"Show passwords");
                if ui.button("Export TXT").clicked(){self.export(false,ctx.clone());}
                if ui.button("Export JSON").clicked(){self.export(true,ctx.clone());}
                if ui.button("Close book").clicked(){self.document=None;self.loaded_path=None;self.selected=None;self.show_passwords=false;self.status="Address book closed".into();}
            });
            ui.small("Export includes every record and plaintext passwords, regardless of the search filter.");
        });
        if let Some(doc) = self.document.clone() {
            let query = self.search.to_lowercase();
            let columns = [
                "address",
                "user",
                "password",
                "group",
                "comment",
                "legacy-comment",
                "romon-agent",
                "workspace",
                "with-password",
                "id",
            ];
            let rows: Vec<usize> = doc
                .records
                .iter()
                .enumerate()
                .filter(|(_, r)| {
                    query.is_empty()
                        || columns
                            .iter()
                            .filter(|&&c| c != "password")
                            .any(|c| r.column(c).to_lowercase().contains(&query))
                })
                .map(|(i, _)| i)
                .collect();
            ui.label(format!("Showing {} of {}", rows.len(), doc.record_count));
            egui::ScrollArea::horizontal()
                .id_salt("accounts-x")
                .show(ui, |ui| {
                    TableBuilder::new(ui)
                        .striped(true)
                        .resizable(true)
                        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                        .column(Column::initial(45.0))
                        .columns(Column::initial(150.0).at_least(65.0), columns.len())
                        .max_scroll_height(320.0)
                        .header(26.0, |mut header| {
                            for title in [
                                "№",
                                "Address",
                                "User",
                                "Password",
                                "Group",
                                "Comment",
                                "Legacy comment",
                                "RoMON",
                                "Workspace",
                                "With password",
                                "ID",
                            ] {
                                header.col(|ui| {
                                    ui.strong(title);
                                });
                            }
                        })
                        .body(|body| {
                            body.rows(28.0, rows.len(), |mut row| {
                                let index = rows[row.index()];
                                let record = &doc.records[index];
                                row.set_selected(self.selected == Some(index));
                                row.col(|ui| {
                                    if ui
                                        .selectable_label(
                                            self.selected == Some(index),
                                            (index + 1).to_string(),
                                        )
                                        .clicked()
                                    {
                                        self.selected = Some(index);
                                    }
                                });
                                for name in columns {
                                    row.col(|ui| {
                                        let value = record.column(name);
                                        if name == "password"
                                            && !self.show_passwords
                                            && !value.is_empty()
                                        {
                                            ui.label("••••••••");
                                        } else {
                                            ui.add(egui::Label::new(value).truncate());
                                        }
                                    });
                                }
                                if row.response().clicked() {
                                    self.selected = Some(index);
                                }
                            })
                        });
                });
            ui.separator();
            if let Some(index) = self.selected.filter(|&i| i < doc.records.len()) {
                ui.label(format!(
                    "Record {} · all fields in original order",
                    index + 1
                ));
                egui::ScrollArea::vertical()
                    .id_salt("fields-y")
                    .show(ui, |ui| {
                        for field in &doc.records[index].fields {
                            ui.horizontal_wrapped(|ui| {
                                ui.monospace(format!(
                                    "{} · {} · {} · offset={:#x}",
                                    field.name.unwrap_or("unknown"),
                                    field.id,
                                    field.kind,
                                    field.offset
                                ));
                                if field.name == Some("password") && !self.show_passwords {
                                    ui.label("••••••••");
                                } else {
                                    ui.add(
                                        egui::Label::new(field.value.to_string()).selectable(true),
                                    );
                                }
                            });
                        }
                    });
            } else {
                ui.label(
                    "Select a row to inspect all fields, including unknown and nested fields.",
                );
            }
        }
        if let Some(path) = self.password_path.clone() {
            egui::Window::new("Address book password")
                .collapsible(false)
                .resizable(false)
                .show(&ctx, |ui| {
                    ui.label(path.display().to_string());
                    let response = ui.add_enabled(
                        !self.busy,
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.reveal_input)
                            .hint_text("Password (may be empty)"),
                    );
                    ui.checkbox(&mut self.reveal_input, "Show input");
                    ui.add_enabled_ui(!self.busy, |ui| {
                        let enter =
                            response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        ui.horizontal(|ui| {
                            if ui.button("Decrypt").clicked() || enter {
                                let password = Zeroizing::new(self.password.as_bytes().to_vec());
                                self.password.zeroize();
                                self.load(path.clone(), Some(password), ctx.clone());
                            }
                            if ui.button("Password from file…").clicked()
                                && let Some(file) = rfd::FileDialog::new().pick_file()
                            {
                                match cdb::read_password(&file) {
                                    Ok(password) => {
                                        self.load(path.clone(), Some(password), ctx.clone())
                                    }
                                    Err(e) => self.status = format!("Error: {e}"),
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                self.password_path = None;
                                self.password.zeroize();
                                self.status = "Opening cancelled".into();
                            }
                        });
                    });
                    ui.label(&self.status);
                });
        }
    }
}
impl eframe::App for Viewer {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(ui.style()).inner_margin(16.0))
            .show(ui, |ui| self.draw(ui));
    }
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        // Windows VM drivers may expose only OpenGL 1.1. Wgpu can use Direct3D
        // and the Windows software adapter without requiring an OpenGL driver.
        #[cfg(target_os = "windows")]
        renderer: eframe::Renderer::Wgpu,
        viewport: egui::ViewportBuilder::default()
            .with_icon(
                eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png"))
                    .expect("embedded application icon must be valid PNG"),
            )
            .with_inner_size([1250.0, 760.0])
            .with_min_inner_size([850.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "WinBox CDB Viewer",
        options,
        Box::new(|_| Ok(Box::new(Viewer::new()))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn wait(app: &mut Viewer) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while app.busy {
            app.events();
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    #[test]
    fn encrypted_open_retry_cancel_and_table_render() {
        let ctx = egui::Context::default();
        let mut app = Viewer::new();
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/encrypted.cdb");
        app.load(path.clone(), None, ctx.clone());
        wait(&mut app);
        assert!(app.password_path.is_some());
        assert!(app.document.is_none());
        app.load(
            path.clone(),
            Some(Zeroizing::new(b"wrong".to_vec())),
            ctx.clone(),
        );
        wait(&mut app);
        assert!(app.password_path.is_some());
        assert!(app.document.is_none());
        let mut output = ctx.run_ui(Default::default(), |ui| app.draw(ui));
        assert!(!output.shapes.is_empty());
        output.textures_delta.clear();
        app.load(
            path,
            Some(Zeroizing::new(" passphrase😀 ".as_bytes().to_vec())),
            ctx.clone(),
        );
        wait(&mut app);
        assert!(app.password_path.is_none());
        assert!(app.password.is_empty());
        assert_eq!(app.document.as_ref().unwrap().record_count, 3);
        app.selected = Some(0);
        for show in [false, true] {
            app.show_passwords = show;
            let mut out = ctx.run_ui(Default::default(), |ui| app.draw(ui));
            assert!(!out.shapes.is_empty());
            out.textures_delta.clear();
        }
        app.search = "does not exist".into();
        let mut output = ctx.run_ui(Default::default(), |ui| app.draw(ui));
        output.textures_delta.clear();
        app.load(PathBuf::from("/nonexistent-cdb-test"), None, ctx);
        wait(&mut app);
        assert!(app.document.is_none());
        assert!(app.loaded_path.is_none());
    }
}
