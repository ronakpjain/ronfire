//! Command-line argument parsing for the ronfire server.
//!
//! The parser keeps the positional Unix-socket argument for compatibility and
//! handles the explicit `--config` and `--root` paths used by [`crate::server`].
//! It performs syntax validation only; filesystem policy is applied during
//! startup.

use std::path::PathBuf;

/// Parses the historical socket, config, and document-root options.
pub fn parse_args(
    args: impl IntoIterator<Item = String>,
) -> Result<(String, PathBuf, bool, PathBuf), String> {
    let mut socket_path = None;
    let mut config_path = PathBuf::from("ronfire.conf");
    let mut config_explicit = false;
    let mut root_path = PathBuf::from(".");
    let mut arguments = args.into_iter().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--config" {
            config_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?,
            );
            config_explicit = true;
        } else if let Some(path) = argument.strip_prefix("--config=") {
            if path.is_empty() {
                return Err("--config requires a path".to_string());
            }
            config_path = PathBuf::from(path);
            config_explicit = true;
        } else if argument == "--root" {
            root_path = PathBuf::from(
                arguments
                    .next()
                    .ok_or_else(|| "--root requires a path".to_string())?,
            );
        } else if let Some(path) = argument.strip_prefix("--root=") {
            if path.is_empty() {
                return Err("--root requires a path".to_string());
            }
            root_path = PathBuf::from(path);
        } else if argument.starts_with('-') {
            return Err(format!("unknown option: {argument}"));
        } else if socket_path.replace(argument).is_some() {
            return Err("only one socket path may be specified".to_string());
        }
    }
    Ok((
        socket_path.unwrap_or_else(|| "/tmp/ronfire.sock".to_string()),
        config_path,
        config_explicit,
        root_path,
    ))
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn keeps_positional_socket_and_accepts_config_and_root() {
        assert_eq!(
            parse_args([
                "ronfire".to_string(),
                "/tmp/test.sock".to_string(),
                "--config".to_string(),
                "/etc/ronfire.conf".to_string(),
                "--root".to_string(),
                "/srv/site".to_string(),
            ])
            .unwrap(),
            (
                "/tmp/test.sock".to_string(),
                "/etc/ronfire.conf".into(),
                true,
                "/srv/site".into(),
            )
        );
    }

    #[test]
    fn default_config_and_root_are_implicit() {
        assert_eq!(
            parse_args(["ronfire".to_string()]).unwrap(),
            (
                "/tmp/ronfire.sock".to_string(),
                "ronfire.conf".into(),
                false,
                ".".into(),
            )
        );
    }
}
