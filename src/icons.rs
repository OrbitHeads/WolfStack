// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Icon pack management — scan, install, and serve Linux icon themes
//!
//! Supports the freedesktop.org icon theme specification so users can install
//! any standard Linux icon pack (Candy, Papirus, Tela, etc.) and use it
//! throughout the WolfStack UI.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::info;

/// Where custom-installed icon packs are stored
const ICON_PACKS_DIR: &str = "/etc/wolfstack/icon-packs";

/// Standard system icon theme paths to scan
const SYSTEM_ICON_DIRS: &[&str] = &[
    "/usr/share/icons",
    "/usr/local/share/icons",
];

/// Mapping from WolfStack semantic icon names to freedesktop.org standard names.
/// The frontend sends these semantic names; we resolve them to actual files.
pub fn semantic_to_freedesktop() -> HashMap<&'static str, &'static [&'static str]> {
    let mut m: HashMap<&str, &[&str]> = HashMap::new();
    // Navigation — verified against Candy, Papirus, Mint-Y
    m.insert("home",           &["user-home", "go-home", "folder-home", "start-here-kde"]);
    m.insert("settings",       &["preferences", "preferences-system", "cs-themes", "configure", "system-settings"]);
    m.insert("network",        &["network-workgroup", "preferences-system-network", "network-wired", "network-server"]);
    m.insert("globe",          &["applications-internet", "internet-web-browser", "web-browser"]);
    m.insert("appstore",       &["system-software-install", "gnome-software", "applications-other", "folder-download"]);
    m.insert("warning",        &["dialog-warning", "emblem-warning", "folder-important"]);
    m.insert("help",           &["help-faq", "help-about", "help-contents", "system-help"]);
    m.insert("add",            &["list-add", "add", "contact-new", "folder-new"]);
    m.insert("logout",         &["system-log-out", "application-exit", "cs-user"]);
    // Settings tabs
    m.insert("palette",        &["preferences-desktop-theme", "cs-cat-appearance", "cs-themes", "applications-graphics"]);
    m.insert("bell",           &["bell", "preferences-desktop-notification", "notification-active", "notifications", "cs-notifications"]);
    m.insert("robot",          &["utilities-terminal", "application-x-executable", "applications-development"]);
    m.insert("package",        &["folder-tar", "folder-deb", "applications-utilities", "package-x-generic"]);
    m.insert("lock",           &["system-lock-screen", "folder-locked", "security-high", "dialog-password", "changes-prevent"]);
    m.insert("heart",          &["emblem-favorite", "favorites", "folder-favorites", "love"]);
    // Components
    m.insert("shield",         &["security-high", "folder-locked", "network-server-security", "preferences-system-network"]);
    m.insert("satellite",      &["network-wireless-connected-100", "network-wireless", "network-transmit-receive"]);
    m.insert("save",           &["drive-harddisk", "media-floppy", "document-save"]);
    m.insert("scale",          &["preferences-desktop-display", "cs-display", "video-display", "utilities-system-monitor"]);
    m.insert("database",       &["folder-database", "drive-multidisk", "network-server"]);
    m.insert("certbot",        &["certificate-server", "folder-locked", "security-high"]);
    // Storage
    m.insert("cloud",          &["folder-cloud", "weather-overcast", "folder-gdrive", "folder-nextcloud"]);
    m.insert("folder",         &["folder", "inode-directory", "gtk-directory", "stock_folder"]);
    m.insert("folder-open",    &["folder-open", "folder-visiting"]);
    m.insert("disk",           &["drive-harddisk", "drive-removable-media", "drive-multidisk"]);
    // Containers
    m.insert("docker",         &["folder-docker", "docker", "application-x-container", "applications-utilities"]);
    m.insert("container",      &["folder-tar", "folder-deb", "applications-utilities", "package-x-generic"]);
    m.insert("computer",       &["computer", "user-desktop", "cs-desktop"]);
    // Status
    m.insert("fire",           &["dialog-warning", "emblem-important", "folder-important"]);
    m.insert("chat",           &["internet-group-chat", "folder-mail", "preferences-desktop-notification"]);
    m.insert("email",          &["internet-mail", "mail-unread", "folder-mail", "evolution"]);
    m.insert("rocket",         &["media-playback-playing", "system-run", "media-playback-start"]);
    m.insert("lightning",      &["battery-full-charging", "battery-good-charging", "weather-storm"]);
    m.insert("laptop",         &["computer", "user-desktop", "cs-desktop"]);
    m.insert("brain",          &["preferences", "preferences-system", "applications-development"]);
    m.insert("lightbulb",      &["dialog-information", "help-faq", "preferences-desktop-accessibility"]);
    m.insert("document",       &["folder-text", "text-x-generic", "folder-documents", "document-new"]);
    m.insert("pin",            &["folder-bookmark", "folder-favorites", "bookmark-new"]);
    m.insert("link",           &["emblem-symbolic-link", "folder-remote", "folder-network"]);
    m.insert("clipboard",      &["edit-paste", "edit-copy", "accessories-clipboard", "folder-notes"]);
    m.insert("chart",          &["utilities-system-monitor", "folder-chart", "gnome-system-monitor"]);
    m.insert("chart-up",       &["folder-chart", "go-up", "utilities-system-monitor"]);
    m.insert("wrench",         &["preferences", "preferences-other", "preferences-system"]);
    m.insert("tools",          &["preferences", "preferences-system", "applications-system"]);
    m.insert("edit",           &["accessories-text-editor", "text-editor", "folder-text"]);
    m.insert("search",         &["edit-find", "system-search", "folder-recent"]);
    m.insert("image",          &["folder-image", "folder-pictures", "image-x-generic", "applications-graphics"]);
    m.insert("key",            &["dialog-password", "folder-locked", "changes-allow"]);
    m.insert("megaphone",      &["notification-active", "notifications", "preferences-desktop-notification"]);
    // File types
    m.insert("file-code",      &["applications-development", "text-x-script", "folder-development"]);
    m.insert("file-config",    &["preferences", "text-x-generic", "folder-script"]);
    m.insert("file-archive",   &["folder-tar", "application-x-archive", "package-x-generic"]);
    m.insert("file-image",     &["folder-image", "image-x-generic", "folder-pictures"]);
    m.insert("file-text",      &["folder-text", "text-plain", "text-x-generic"]);
    m.insert("file-data",      &["folder-database", "application-x-sqlite3", "drive-multidisk"]);
    m.insert("file-shell",     &["utilities-terminal", "text-x-script", "folder-script"]);
    // Monitoring
    m.insert("cpu",            &["utilities-system-monitor", "cpu", "hwinfo"]);
    m.insert("memory",         &["drive-harddisk", "utilities-system-monitor", "media-memory"]);
    m.insert("swap",           &["drive-removable-media", "view-refresh", "system-reboot"]);
    m.insert("load",           &["utilities-system-monitor", "folder-chart", "go-up"]);
    m.insert("service",        &["preferences", "preferences-system", "system-run"]);
    // Misc
    m.insert("door",           &["system-log-out", "application-exit", "cs-user"]);
    m.insert("wolf",           &["emblem-system", "applications-system", "security-high"]);
    m.insert("gamepad",        &["applications-games", "input-gaming", "folder-games"]);
    m.insert("music",          &["folder-music", "audio-x-generic", "applications-multimedia"]);
    m.insert("camera",         &["accessories-camera", "camera-photo", "folder-pictures"]);
    m.insert("cart",           &["folder-download", "applications-other", "system-software-install"]);
    m.insert("money",          &["accessories-calculator", "folder-calculate", "applications-office"]);
    m.insert("book",           &["accessories-dictionary", "folder-book", "help-contents"]);
    m.insert("lab",            &["applications-science", "applications-development", "utilities-system-monitor"]);
    m.insert("star",           &["emblem-favorite", "favorites", "folder-favorites"]);
    m.insert("runner",         &["media-playback-playing", "system-run", "media-playback-start"]);
    // App-specific icons (for app store entries)
    m.insert("fox",            &["firefox", "internet-web-browser", "applications-internet"]);
    m.insert("elephant",       &["folder-database", "drive-multidisk", "database"]);
    m.insert("whale",          &["folder-docker", "docker", "applications-utilities"]);
    m.insert("penguin",        &["folder-linux", "applications-system", "utilities-terminal"]);
    m.insert("movie",          &["folder-video", "folder-videos", "applications-multimedia"]);
    m.insert("target",         &["folder-bookmark", "folder-important", "emblem-favorite"]);
    m.insert("alien",          &["applications-games", "folder-games", "input-gaming"]);
    m
}

/// Fallback icon names to try when no semantic match is found.
/// These are common icons that most freedesktop packs include.
const FALLBACK_ICONS: &[&str] = &[
    "applications-other",
    "application-default-icon",
    "preferences",
    "folder",
    "emblem-system",
    "applications-utilities",
    "text-x-generic",
];

/// Metadata about an installed icon pack
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IconPack {
    pub id: String,
    pub name: String,
    pub comment: String,
    pub path: String,
    /// "system" | "custom"
    pub source: String,
    /// Whether this pack has scalable SVGs
    pub has_scalable: bool,
    /// Number of icons found
    pub icon_count: usize,
    /// Sample icon names available
    #[serde(default)]
    pub sample_icons: Vec<String>,
}

/// Parse a freedesktop index.theme file to extract name and comment
fn parse_index_theme(path: &Path) -> Option<(String, String)> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut name = String::new();
    let mut comment = String::new();
    let mut in_icon_theme = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[Icon Theme]" {
            in_icon_theme = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_icon_theme = false;
            continue;
        }
        if !in_icon_theme { continue; }
        if let Some(val) = trimmed.strip_prefix("Name=") {
            if name.is_empty() { name = val.to_string(); }
        } else if let Some(val) = trimmed.strip_prefix("Comment=") {
            if comment.is_empty() { comment = val.to_string(); }
        }
    }
    if name.is_empty() { return None; }
    Some((name, comment))
}

/// Search an icon theme directory for a named icon, returning the file path.
/// Prefers scalable SVGs, then larger PNGs.
///
/// Handles all common freedesktop.org icon theme layouts:
///   - Papirus-style:  `48x48/apps/icon.svg`   (size-first, NxN)
///   - Mint-Y-style:   `apps/48/icon.svg`       (category-first, bare number)
///   - Candy-style:    `apps/scalable/icon.svg`  (category-first, scalable)
///   - Flat:           `scalable/apps/icon.svg`  (scalable-first)
pub fn find_icon_file(theme_dir: &Path, icon_name: &str) -> Option<PathBuf> {
    let scalable_dirs = ["scalable", "symbolic"];
    // NxN format (Papirus, Adwaita, etc.)
    let nxn_sizes = ["512x512", "256x256", "128x128", "96x96", "64x64",
                     "48x48", "42x42", "32x32", "24x24", "22x22", "18x18", "16x16"];
    // Bare number format (Mint-Y, elementary, etc.)
    let bare_sizes = ["256", "128", "96", "64", "48", "32", "24", "22", "16"];
    let context_dirs = ["apps", "actions", "categories", "devices", "emblems",
                        "mimetypes", "places", "status", "preferences", "panel",
                        "stock", "legacy"];
    let extensions = ["svg", "png", "xpm"];

    // 1. scalable/category/ or symbolic/category/ (flat scalable-first)
    for sc in &scalable_dirs {
        for ctx in &context_dirs {
            for ext in &extensions {
                let p = theme_dir.join(sc).join(ctx).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
        for ext in &extensions {
            let p = theme_dir.join(sc).join(format!("{}.{}", icon_name, ext));
            if p.exists() { return Some(p); }
        }
    }

    // 2. category/scalable/ or category/symbolic/ (Candy-style)
    for ctx in &context_dirs {
        for sc in &scalable_dirs {
            for ext in &extensions {
                let p = theme_dir.join(ctx).join(sc).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    // 3. category/size/ — bare numbers, biggest first (Mint-Y-style)
    for ctx in &context_dirs {
        for sz in &bare_sizes {
            for ext in &extensions {
                let p = theme_dir.join(ctx).join(sz).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    // 4. NxN/category/ — biggest first (Papirus-style)
    for sz in &nxn_sizes {
        for ctx in &context_dirs {
            for ext in &extensions {
                let p = theme_dir.join(sz).join(ctx).join(format!("{}.{}", icon_name, ext));
                if p.exists() { return Some(p); }
            }
        }
    }

    None
}

/// Resolve a WolfStack semantic icon name to a file in the given theme.
/// Tries: specific candidates → semantic name directly → fallback icons.
pub fn resolve_icon(theme_dir: &Path, semantic_name: &str) -> Option<PathBuf> {
    let map = semantic_to_freedesktop();
    if let Some(candidates) = map.get(semantic_name) {
        for name in *candidates {
            if let Some(p) = find_icon_file(theme_dir, name) {
                return Some(p);
            }
        }
    }
    // Try the semantic name directly (some packs may have custom names)
    if let Some(p) = find_icon_file(theme_dir, semantic_name) {
        return Some(p);
    }
    // Use a fallback icon so we never show a mix of emojis and pack icons
    resolve_fallback(theme_dir)
}

/// Find any generic fallback icon from the pack
fn resolve_fallback(theme_dir: &Path) -> Option<PathBuf> {
    for name in FALLBACK_ICONS {
        if let Some(p) = find_icon_file(theme_dir, name) {
            return Some(p);
        }
    }
    None
}

/// Scan a directory for valid icon themes (must have index.theme)
fn scan_icon_dir(base: &Path, source: &str) -> Vec<IconPack> {
    let mut packs = Vec::new();
    let entries = match std::fs::read_dir(base) {
        Ok(e) => e,
        Err(_) => return packs,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() { continue; }
        let index = path.join("index.theme");
        if !index.exists() { continue; }
        let (name, comment) = match parse_index_theme(&index) {
            Some(v) => v,
            None => continue,
        };
        // Skip cursor-only themes or hicolor
        let dir_name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if dir_name == "hicolor" || dir_name == "default" { continue; }
        if name.to_lowercase().contains("cursor") { continue; }

        let has_scalable = path.join("scalable").exists()
            || path.join("apps").join("scalable").exists();

        let icon_count = count_icons_rough(&path);

        packs.push(IconPack {
            id: dir_name,
            name,
            comment,
            path: path.to_string_lossy().to_string(),
            source: source.to_string(),
            has_scalable,
            icon_count,
            sample_icons: Vec::new(),
        });
    }
    packs
}

/// Rough count of icon files in a theme
fn count_icons_rough(dir: &Path) -> usize {
    let mut count = 0;
    // Just count in a few common subdirectories to keep it fast
    let check_dirs = ["scalable/apps", "48x48/apps", "scalable/places", "scalable/categories",
                      "apps/scalable", "apps/48", "places/scalable"];
    for sub in &check_dirs {
        let p = dir.join(sub);
        if let Ok(entries) = std::fs::read_dir(&p) {
            count += entries.flatten()
                .filter(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    name.ends_with(".svg") || name.ends_with(".png")
                })
                .count();
        }
    }
    count
}

/// Scan all known icon directories for available themes
pub fn scan_all_packs() -> Vec<IconPack> {
    let mut packs = Vec::new();

    // System icon dirs
    for dir in SYSTEM_ICON_DIRS {
        packs.extend(scan_icon_dir(Path::new(dir), "system"));
    }

    // Custom-installed packs
    let custom_dir = Path::new(ICON_PACKS_DIR);
    if custom_dir.exists() {
        packs.extend(scan_icon_dir(custom_dir, "custom"));
    }

    // Sort: custom first, then by name
    packs.sort_by(|a, b| {
        if a.source != b.source {
            if a.source == "custom" { return std::cmp::Ordering::Less; }
            return std::cmp::Ordering::Greater;
        }
        a.name.cmp(&b.name)
    });

    packs
}

/// Install an icon pack from a GitHub repository URL.
/// Clones with --depth 1 to save space, moves to /etc/wolfstack/icon-packs/{name}.
pub async fn install_from_github(url: &str) -> Result<IconPack, String> {
    // Validate URL looks like a GitHub repo
    if !url.contains("github.com/") {
        return Err("URL must be a GitHub repository (e.g. https://github.com/user/repo)".into());
    }

    // Extract repo name from URL
    let repo_name = url
        .trim_end_matches('/')
        .trim_end_matches(".git")
        .rsplit('/')
        .next()
        .ok_or("Could not parse repository name from URL")?
        .to_string();

    let install_dir = PathBuf::from(ICON_PACKS_DIR);
    let dest = install_dir.join(&repo_name);

    if dest.exists() {
        return Err(format!("Icon pack '{}' is already installed", repo_name));
    }

    // Ensure parent dir exists
    std::fs::create_dir_all(&install_dir)
        .map_err(|e| format!("Failed to create icon packs directory: {}", e))?;

    info!("Installing icon pack from {} to {:?}", url, dest);

    // Clone with depth 1
    let output = tokio::process::Command::new("git")
        .args(["clone", "--depth", "1", url, &dest.to_string_lossy()])
        .output()
        .await
        .map_err(|e| format!("Failed to run git clone: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git clone failed: {}", stderr));
    }

    // Remove .git directory to save space
    let git_dir = dest.join(".git");
    if git_dir.exists() {
        let _ = std::fs::remove_dir_all(&git_dir);
    }

    // Verify it's a valid icon theme
    let index = dest.join("index.theme");
    if !index.exists() {
        // Some repos put the theme inside a subdirectory — check one level deep
        let mut found = false;
        if let Ok(entries) = std::fs::read_dir(&dest) {
            for entry in entries.flatten() {
                if entry.path().join("index.theme").exists() {
                    // Move subdirectory contents up
                    let sub = entry.path();
                    let tmp = install_dir.join(format!("{}-tmp", repo_name));
                    std::fs::rename(&sub, &tmp)
                        .map_err(|e| format!("Failed to reorganize: {}", e))?;
                    std::fs::remove_dir_all(&dest)
                        .map_err(|e| format!("Failed to clean up: {}", e))?;
                    std::fs::rename(&tmp, &dest)
                        .map_err(|e| format!("Failed to finalize: {}", e))?;
                    found = true;
                    break;
                }
            }
        }
        if !found {
            let _ = std::fs::remove_dir_all(&dest);
            return Err("Repository does not contain a valid icon theme (no index.theme found)".into());
        }
    }

    // Parse and return the pack info
    let (name, comment) = parse_index_theme(&dest.join("index.theme"))
        .unwrap_or_else(|| (repo_name.clone(), String::new()));

    let has_scalable = dest.join("scalable").exists()
        || dest.join("apps").join("scalable").exists();

    let mut sample_icons = Vec::new();
    let semantic_map = semantic_to_freedesktop();
    for (semantic, _) in &semantic_map {
        if sample_icons.len() >= 6 { break; }
        if resolve_icon(&dest, semantic).is_some() {
            sample_icons.push(semantic.to_string());
        }
    }

    let icon_count = count_icons_rough(&dest);

    Ok(IconPack {
        id: repo_name,
        name,
        comment,
        path: dest.to_string_lossy().to_string(),
        source: "custom".to_string(),
        has_scalable,
        icon_count,
        sample_icons,
    })
}

/// Remove a custom-installed icon pack
pub fn remove_pack(pack_id: &str) -> Result<(), String> {
    let dest = PathBuf::from(ICON_PACKS_DIR).join(pack_id);
    if !dest.exists() {
        return Err(format!("Icon pack '{}' not found", pack_id));
    }
    // Safety: only allow removing from our managed directory
    if !dest.starts_with(ICON_PACKS_DIR) {
        return Err("Cannot remove system icon themes".into());
    }
    std::fs::remove_dir_all(&dest)
        .map_err(|e| format!("Failed to remove icon pack: {}", e))?;
    info!("Removed icon pack '{}'", pack_id);
    Ok(())
}

/// Get the MIME type for an icon file
pub fn icon_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("xpm") => "image/x-xpixmap",
        _ => "application/octet-stream",
    }
}

/// Get the list of all semantic icon names (for the frontend)
pub fn semantic_names() -> Vec<&'static str> {
    let mut names: Vec<&str> = semantic_to_freedesktop().keys().copied().collect();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_map_complete() {
        let map = semantic_to_freedesktop();
        // Every entry should have at least one freedesktop name
        for (key, candidates) in &map {
            assert!(!candidates.is_empty(), "semantic icon '{}' has no candidates", key);
        }
    }

    #[test]
    fn test_icon_mime_types() {
        assert_eq!(icon_mime(Path::new("foo.svg")), "image/svg+xml");
        assert_eq!(icon_mime(Path::new("foo.png")), "image/png");
        assert_eq!(icon_mime(Path::new("foo.xpm")), "image/x-xpixmap");
    }

    #[test]
    fn test_parse_index_theme() {
        let dir = std::env::temp_dir().join("wolfstack-test-icons");
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(dir.join("index.theme"), "[Icon Theme]\nName=Test Theme\nComment=A test\n").unwrap();
        let result = parse_index_theme(&dir.join("index.theme"));
        assert_eq!(result, Some(("Test Theme".into(), "A test".into())));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
