use anyhow::{anyhow, ensure, Context, Error, Result};
use clap::Parser;
use crc::{Crc, CRC_32_ISO_HDLC};
use env_logger::Builder;
use lazy_static::lazy_static;
use log::{debug, error, info, warn};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::option::Option;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::str;
use std::time;
use uzers::os::unix::UserExt;
use uzers::switch;
use uzers::{User, Users, UsersCache};

#[cfg(test)]
use mockall::automock;

#[cfg_attr(test, automock)]
trait SwitchUserGuardTrait {
    fn drop_trait(self);
}

impl SwitchUserGuardTrait for Box<switch::SwitchUserGuard> {
    fn drop_trait(self) {
        drop(*self);
    }
}

#[cfg_attr(test, automock)]
trait SwitchUserTrait<T> where T: SwitchUserGuardTrait {
    fn switch_user_group(
        &self,
        uid: uzers::uid_t,
        gid: uzers::gid_t,
    ) -> Result<T, io::Error>;
}

struct SwitchUser;

impl SwitchUserTrait<Box<switch::SwitchUserGuard>> for SwitchUser {
    fn switch_user_group(
        &self,
        uid: uzers::uid_t,
        gid: uzers::gid_t,
    ) -> Result<Box<switch::SwitchUserGuard>, io::Error> {
        switch::switch_user_group(uid, gid)
            .map(|switch_user_guard| Box::new(switch_user_guard))
    }
}

// Switches the effective uid to the given user
fn switch_user<T, U, V>(
    user_name_option: Option<&str>,
    user_table: &T,
    switch_user_trait: &U,
) -> Result<(User, Option<V>)>
where
    T: Users,
    U: SwitchUserTrait<V>,
    V: SwitchUserGuardTrait
{
    match user_name_option {
        Some(user_name) => {
            info!("Attempting to change to user {:?}", user_name);
            let user = user_table
                .get_user_by_name(&user_name)
                .context(format!("No user with username {:?}", user_name))?;
            let guard = switch_user_trait
                .switch_user_group(user.uid(), user.primary_group_id())
                .context(format!(
                    "Couldn't seteuid to user with username {:?}",
                    user_name
                ))?;
            Ok((User::clone(&user), Some(guard)))
        }
        None => {
            let current_user_name = user_table
                .get_current_username()
                .ok_or_else(|| Error::msg("Couldn't get username of current user"))?;
            info!("Current user is {:?}, not changing", current_user_name);
            user_table
                .get_user_by_name(&current_user_name)
                .ok_or_else(|| {
                    Error::msg(format!(
                        "Couldn't get user with username {:?}",
                        current_user_name
                    ))
                })
                .map(|current_user| (User::clone(&current_user), None))
        }
    }
}

#[cfg_attr(test, automock)]
trait MetadataTrait {
    fn uid_trait(&self) -> u32;
    fn mode_trait(&self) -> u32;
    fn modified_trait(&self) -> Result<time::SystemTime>;
    fn is_dir_trait(&self) -> bool;
}

impl MetadataTrait for std::fs::Metadata {
    fn uid_trait(&self) -> u32 {
        self.uid()
    }

    fn mode_trait(&self) -> u32 {
        self.mode()
    }

    fn modified_trait(&self) -> Result<time::SystemTime> {
        self.modified().map_err(anyhow::Error::from)
    }

    fn is_dir_trait(&self) -> bool {
        self.is_dir()
    }
}

#[cfg_attr(test, automock)]
trait FsTrait {
    fn metadata(&self, path: &Path) -> Result<Box<dyn MetadataTrait>>;
    fn read_to_string(&self, path: &Path) -> Result<String>;
    fn create_dir_all(&self, path: &Path) -> Result<()>;
    fn write(&self, path: &Path, contents: &str) -> Result<()>;
    fn set_permissions(&self, path: &Path, perm: fs::Permissions) -> Result<()>;
}

struct StdFs;

impl FsTrait for StdFs {
    fn metadata(&self, path: &Path) -> Result<Box<dyn MetadataTrait>> {
        fs::metadata(path)
            .map(|metadata| Box::new(metadata) as Box<dyn MetadataTrait>)
            .map_err(anyhow::Error::from)
    }

    fn read_to_string(&self, path: &Path) -> Result<String> {
        fs::read_to_string(path).map_err(anyhow::Error::from)
    }

    fn create_dir_all(&self, path: &Path) -> Result<()> {
        fs::create_dir_all(path).map_err(anyhow::Error::from)
    }

    fn write(&self, path: &Path, contents: &str) -> Result<()> {
        fs::write(path, contents).map_err(anyhow::Error::from)
    }

    fn set_permissions(&self, path: &Path, perm: fs::Permissions) -> Result<()> {
        fs::set_permissions(path, perm).map_err(anyhow::Error::from)
    }
}

// If user_option is Some, ensures the path is owned by, and can be written only by, that user,
// then reads the file at that path
fn ensure_safe_permissions_and_read<U>(
    path: &Path,
    user_option: Option<&User>,
    fs_trait: &U,
) -> Result<(String, Box<dyn MetadataTrait>)>
where
    U: FsTrait,
{
    let metadata = fs_trait
        .metadata(path)
        .context(format!("Couldn't stat {:?}", path))?;

    if let Some(user) = user_option {
        ensure!(
            metadata.uid_trait() == user.uid(),
            format!("{:?} not owned by {:?}", path, user.name())
        );
        ensure!(
            metadata.mode_trait() & 0o022 == 0,
            format!("{:?} is writable by group or world", path)
        );
        info!("{:?} has correct permissions", path);
    }
    info!("Reading {:?}", path);
    fs_trait
        .read_to_string(path)
        .context(format!("Could not read {:?}", path))
        .map(|read_string| (read_string, metadata))
}

lazy_static! {
    // Space-delimited tokens, except those within double quotes,
    // where double quotes inside double quotes may be escaped
    // with a backslash, and any token beginning with @ is included
    // as part of the next token
    static ref REGEX_SPACE_DELIMITED: Regex = Regex::new(r#"(@[^ ]* +)?(([^ "]*"([^\\]|\\.)*?"[^ "]*)+|[^ "]+)"#).unwrap();
}

// Parses the source definitions &str into a HashMap of sources to a tuple
// of a URL template and any options
fn get_source_defs(source_defs_string: &str)
    -> Result<HashMap<String, (String, Option<String>)>> 
{
    let mut source_defs_map = HashMap::new();
    for line in source_defs_string.lines() {
        let line_tokens: Vec<String> = REGEX_SPACE_DELIMITED.find_iter(line)
            .map(|m| m.as_str().to_string())
            .collect();

        // Line is empty or begins with #
        if line_tokens.len() == 0
                || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#' {
            continue;
        }

        if line_tokens.len() < 2 {
            warn!("Skipping invalid source line: {}", line);
            continue;
        }

        let (line_key, line_url, line_opts) = if line_tokens.get(2)
            .and_then(|token| reqwest::Url::parse(token).ok())
            .map(String::from)
            .is_some() {
                (
                    line_tokens.get(1).unwrap().to_string(),
                    line_tokens.get(2).unwrap().to_string(),
                    Some(line_tokens.get(0).unwrap().to_string())
                )
            } else {
                (
                    line_tokens.get(0).unwrap().to_string(),
                    line_tokens.get(1).unwrap().to_string(),
                    None
                )
            };
        if source_defs_map.contains_key(&line_key) {
            warn!(
                "Duplicate source definition for {}; later definition \"{:?}\" will override earlier definition \"{:?}\"",
                line_key,
                (&line_url, &line_opts),
                source_defs_map.get(&line_key).unwrap()
            );
        }
        source_defs_map.insert(line_key, (line_url, line_opts));
    }

    ensure!(
        !source_defs_map.is_empty(),
        "Read sources definitions file, but no sources were defined in it"
    );

    Ok(source_defs_map)
}

// Construct the filename in which the cached response lives
fn get_cache_filename(
    source_name: &str,
    line_tokens: &[String],
    cache_directory: &Path
) -> PathBuf {
    let mut source_name_line_tokens = vec![source_name.to_string()];
    source_name_line_tokens.extend_from_slice(line_tokens);

    // Canonicalise user definition line by combining whitespace
    let line_join_ascii_whitespace = source_name_line_tokens.join(" ");

    let crc_line =
        Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(line_join_ascii_whitespace.as_bytes());

    lazy_static! {
        static ref REGEX_FILENAME: Regex = Regex::new(r"[^[:alnum:]_\.\-]+").unwrap();
    }

    // Replace all characters that aren't alphanumeric, _, ., or - with -
    let line_join_hyphen = source_name_line_tokens
        .iter()
        .map(|token| {
            REGEX_FILENAME
                .replace_all(token, |_: &Captures| "-")
                .into_owned()
        })
        .collect::<Vec<String>>()
        .join("_");

    let cache_filename = format!("{:x}-{}", crc_line, line_join_hyphen);

    cache_directory.join(cache_filename)
}

// Returns Err(_) if the modified time is not available in the metadata,
// Ok(false) if the modified time is earlier than cache_stale seconds ago, and
// Ok(true) if the modified time is later than cache_stale seconds ago
fn is_cache_fresh(metadata: Box<dyn MetadataTrait>, cache_stale: u64) -> Result<bool> {
    Ok(time::SystemTime::now()
        .duration_since(metadata.modified_trait()?)?
        .as_secs()
        <= cache_stale)
}

// Construct URL, given URL template and tokens
fn construct_url<T: AsRef<str>>(
    url_template: &str,
    tokens: &[T],
) -> Result<String> {
    lazy_static! {
        static ref REGEX_URL: Regex = Regex::new(r"\{(?P<index>[[:digit:]]+)\}").unwrap();
    }

    let mut replacement_successful = true;
    let url = REGEX_URL
        .replace_all(&url_template, |caps: &Captures| {
            let index = caps.name("index").unwrap().as_str().parse::<usize>().unwrap() - 1;
            match tokens.get(index) {
                Some(x) => x.as_ref(),
                None => {
                    replacement_successful = false;
                    ""
                }
            }
        }).to_string();

    ensure!(
        replacement_successful,
        format!("Not enough parameters")
    );
    Ok(url)
}

#[cfg_attr(test, automock)]
trait HttpClientTrait {
    fn request_from_url(&self, url: String, request_timeout: u64) -> Result<String>;
}

#[cfg(feature = "curl")]
struct CurlHttpClient;

#[cfg(feature = "curl")]
impl HttpClientTrait for CurlHttpClient {
    // Make request, timing out after request_timeout seconds
    fn request_from_url(&self, url: String, request_timeout: u64) -> Result<String> {
        debug!("Using curl");
        info!("Making request to {}", url);
        let mut response = Vec::new();
        let mut easy = curl::easy::Easy::new();
        easy.url(&url)?;
        easy.timeout(time::Duration::from_secs(request_timeout))?;
        easy.follow_location(true)?;
        {
            let mut transfer = easy.transfer();
            transfer.write_function(|data| {
                response.extend_from_slice(data);
                Ok(data.len())
            })?;
            transfer.perform()
        }
        .context("Transfer failed in libcurl")?;

        // If response code is not 200, return Error
        let response_code = easy.response_code()?;
        ensure!(
            response_code == 200,
            format!("Response code was {}, not 200", response_code)
        );

        info!("Request was successful");
        Ok(String::from_utf8(response)?)
    }
}

#[cfg(feature = "reqwest")]
struct ReqwestHttpClient;

#[cfg(feature = "reqwest")]
impl HttpClientTrait for ReqwestHttpClient {
    // Make request, timing out after request_timeout seconds
    fn request_from_url(&self, url: String, request_timeout: u64) -> Result<String> {
        let parsed_url = reqwest::Url::parse(&url)
            .context(format!("Invalid URL: {}", url))?;

        debug!("Using reqwest");
        info!("Making request to {}", url);

        reqwest::blocking::Client::builder()
            .timeout(time::Duration::from_secs(request_timeout))
            .build()
            .context("Could not create reqwest client")?
            .get(parsed_url)
            .send()
            .context("Transfer failed in reqwest")?
            .error_for_status()
            .context("Response code was not succesful")?
            .text()
            .context("Could not decode response")
    }
}

fn write_to_cache<U>(cache_path: PathBuf, response_str: &str, fs_trait: &U) -> Result<()>
where
    U: FsTrait,
{
    let cache_path_parent = cache_path
        .parent()
        .ok_or_else(|| Error::msg(format!("Couldn't get path parent of {:?}", cache_path)))?;
    match fs_trait.metadata(cache_path_parent) {
        Ok(cache_path_parent_metadata) => {
            ensure!(
                cache_path_parent_metadata.is_dir_trait(),
                format!("{:?} exists but is not a directory", cache_path_parent)
            );
            info!("Found cache directory at {:?}", cache_path_parent);
        }
        Err(_) => {
            info!("Creating cache directory at {:?}", cache_path_parent);
            fs_trait.create_dir_all(cache_path_parent).context(format!(
                "Couldn't create cache directory at {:?}",
                cache_path_parent
            ))?;
        }
    }

    info!("Saving response to cache location {:?}", cache_path);
    fs_trait
        .write(&cache_path, response_str)
        .context(format!("Couldn't write cache at {:?}", cache_path))?;
    fs_trait
        .set_permissions(&cache_path, fs::Permissions::from_mode(0o644))
        .context(format!("Couldn't set permissions at {:?}", cache_path))?;
    Ok(())
}

// Parses the user definitions line, returning the source name, the source
// definition, the user tokens to be used to replace the tokens in the URL
// template, and any user options
// If the second token is the name of a source in source_defs_map, then
// assumes the first token is the user options
// Otherwise, if the first token is the name of a source in source_defs_map,
// assumes there are no user options
fn parse_user_def_line(
    user_defs_line: &str,
    source_defs_map: &HashMap<String, (String, Option<String>)>
) -> Result<Option<(
        (String, (String, Option<String>)),
        Vec<String>,
        Option<String>
)>> {
    let user_line_tokens: Vec<String> = REGEX_SPACE_DELIMITED.find_iter(user_defs_line)
        .map(|m| m.as_str().to_string())
        .collect();

    // Line is empty or begins with #
    if user_line_tokens.len() == 0
            || user_line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#' {
        return Ok(None);
    }

    user_line_tokens.get(1)
        .and_then(|source_name| source_defs_map.get_key_value(source_name))
        .map(|(source_name, source_def)|
            Some((
                (source_name.to_string(), source_def.to_owned()),
                user_line_tokens.split_at(2).1.to_vec(),
                Some(user_line_tokens.get(0).unwrap().to_string())
            ))
        )
        .or_else(||
            user_line_tokens.get(0)
                .and_then(|source_name| source_defs_map.get_key_value(source_name))
                .map(|(source_name, source_def)|
                    Some((
                        (source_name.to_string(), source_def.to_owned()),
                        user_line_tokens.split_at(1).1.to_vec(),
                        None
                    ))
                )
        )
        .ok_or_else(|| anyhow!("No source definition found for source {}", user_line_tokens.get(0).unwrap()))
}

fn parse_key_line(key_line: &str) -> (Option<String>, String) {
    let key_line_tokens: Vec<regex::Match> = REGEX_SPACE_DELIMITED.find_iter(key_line)
        .collect();

    lazy_static! {
        static ref KNOWN_KEY_TYPES: Vec<&'static str> = vec![
            "ssh-dss",
            "ssh-dss-cert-v01@openssh.com",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "sk-ecdsa-sha2-nistp256@openssh.com",
            "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp384-cert-v01@openssh.com",
            "ecdsa-sha2-nistp521",
            "ecdsa-sha2-nistp521-cert-v01@openssh.com",
            "ssh-ed25519",
            "ssh-ed25519-cert-v01@openssh.com",
            "sk-ssh-ed25519@openssh.com",
            "sk-ssh-ed25519-cert-v01@openssh.com",
            "ssh-rsa",
            "ssh-rsa-cert-v01@openssh.com",
            "ssh-xmss@openssh.com",
            "ssh-xmss-cert-v01@openssh.com"
        ];
    }

    // Line is empty or has one token,
    // or begins with #,
    // or the second token does not correspond to a known key type
    if key_line_tokens.len() < 2
            || key_line_tokens.get(0).unwrap().as_str().chars().next().unwrap_or('#') == '#'
            || !KNOWN_KEY_TYPES.contains(&key_line_tokens.get(1).unwrap().as_str()) {
        (None, key_line.to_string())
    } else {
        let first_token = key_line_tokens.get(0).unwrap();
        (
            Some(first_token.as_str().to_string()),
            key_line[first_token.end()..].trim_start().to_string()
        )
    }
}

fn split_at_first_marker(opts_option: Option<String>) -> (Option<String>, Option<String>) {
    lazy_static! {
        // A marker that starts with @ and ends at a space
        static ref REGEX_ATSIGN_SPACE_DELIMITED: Regex = Regex::new(r#"@[^ ]*"#).unwrap();
    }

    opts_option.as_ref().and_then(|opts|
        REGEX_ATSIGN_SPACE_DELIMITED.find(&opts)
        .map(|m| m.end())
        .and_then(|marker_end_index| {
            let (marker, opts_rest) = opts.split_at(marker_end_index);
            Some((
                {
                    if marker.is_empty() {
                        None
                    } else {
                        Some(marker.to_string())
                    }
                },
                {
                    let opts_rest_trimmed = opts_rest.trim_start();
                    if opts_rest_trimmed.is_empty() {
                        None
                    } else {
                        Some(opts_rest_trimmed.to_string())
                    }
                }
            ))
        })
    ).unwrap_or_else(
        || (None, opts_option)
    )
}

fn combine_and_strip_markers(
    key_opts_option: Option<String>,
    user_opts_option: Option<String>,
    source_opts_option: Option<String>
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>
) {
    let (key_marker, key_opts) = split_at_first_marker(key_opts_option);
    let (user_marker, user_opts) = split_at_first_marker(user_opts_option);
    let (source_marker, source_opts) = split_at_first_marker(source_opts_option);

    (
        {
            if [&key_marker, &user_marker, &source_marker].iter().any(
                |marker| marker.as_ref().map_or_else(
                    || false,
                    |marker_string| marker_string == "@revoked"
                )
            ) {
                Some("@revoked".to_string())
            } else if [&key_marker, &user_marker, &source_marker].iter().any(
                |marker| marker.as_ref().map_or_else(
                    || false,
                    |marker_string| marker_string == "@cert-authority"
                )
            ) {
                Some("@cert-authority".to_string())
            } else {
                None
            }
        },
        key_opts,
        user_opts,
        source_opts
    )
}

fn combine_opts(
    key_marker_opts: Option<String>,
    user_marker_opts: Option<String>,
    source_marker_opts: Option<String>
) -> String {
    lazy_static! {
        // Comma-delimited tokens, except those within double quotes
        static ref REGEX_COMMA_DELIMITED: Regex = Regex::new(r#"([^,"]*"([^\\]|\\.)*?"[^,"]*)+|[^,"]+"#).unwrap();
        static ref NONDUPLICABLE_OPTS: Vec<&'static str> = vec![
            "command",
            "principals",
            "from"
        ];
    }

    let (
        marker_option,
        key_opts,
        user_opts,
        source_opts
    ) = combine_and_strip_markers(key_marker_opts, user_marker_opts, source_marker_opts);

    let mut key_opts_tokens = REGEX_COMMA_DELIMITED
        .find_iter(&key_opts.unwrap_or("".to_string()))
        .map(|m| m.as_str().to_string())
        .collect::<Vec<_>>();

    let mut user_opts_tokens = REGEX_COMMA_DELIMITED
        .find_iter(&user_opts.unwrap_or("".to_string()))
        .map(|m| m.as_str().to_string())
        .collect::<Vec<_>>();

    let mut source_opts_tokens = REGEX_COMMA_DELIMITED
        .find_iter(&source_opts.unwrap_or("".to_string()))
        .map(|m| m.as_str().to_string())
        .collect::<Vec<_>>();

    let mut source_nonduplicable_opts = HashMap::new();

    source_opts_tokens.retain(|source_opt| {
        for &nonduplicable_opt in NONDUPLICABLE_OPTS.iter() {
            if source_opt.starts_with(nonduplicable_opt) {
                if let Some(existing_opt) = source_nonduplicable_opts.get(nonduplicable_opt) {
                    warn!(
                        "Source definition line specifies option {:?} more than once; keeping only the first specification {:?}, removing subsequent specification {:?}",
                        nonduplicable_opt,
                        existing_opt,
                        source_opt
                    );
                    return false;
                } else {
                    source_nonduplicable_opts.insert(nonduplicable_opt, source_opt.clone());
                }
            }
        }
        return true;
    });

    let mut user_nonduplicable_opts = HashMap::new();

    user_opts_tokens.retain(|user_opt| {
        for &nonduplicable_opt in NONDUPLICABLE_OPTS.iter() {
            if user_opt.starts_with(nonduplicable_opt) {
                if let Some(existing_opt) = source_nonduplicable_opts.get(nonduplicable_opt) {
                    warn!(
                        "Source definition line already specifies option {:?} as {:?}; removing {:?} that was specified in user definition line",
                        nonduplicable_opt,
                        existing_opt,
                        user_opt
                    );
                    return false;
                } else if let Some(existing_opt) = user_nonduplicable_opts.get(nonduplicable_opt) {
                    warn!(
                        "User definition line specifies option {:?} more than once; keeping only the first specification {:?}, removing subsequent specification {:?}",
                        nonduplicable_opt,
                        existing_opt,
                        user_opt
                    );
                    return false;
                } else {
                    user_nonduplicable_opts.insert(nonduplicable_opt, user_opt.clone());
                }
            }
        }
        return true;
    });

    let mut key_nonduplicable_opts = HashMap::new();

    key_opts_tokens.retain(|key_opt| {
        for &nonduplicable_opt in NONDUPLICABLE_OPTS.iter() {
            if key_opt.starts_with(nonduplicable_opt) {
                if let Some(existing_opt) = source_nonduplicable_opts.get(nonduplicable_opt) {
                    warn!(
                        "Source definition line already specifies option {:?} as {:?}; removing {:?} that was specified in fetched key",
                        nonduplicable_opt,
                        existing_opt,
                        key_opt
                    );
                    return false;
                } else if let Some(existing_opt) = user_nonduplicable_opts.get(nonduplicable_opt) {
                    warn!(
                        "User definition line already specifies option {:?} as {:?}; removing {:?} that was specified in fetched key",
                        nonduplicable_opt,
                        existing_opt,
                        key_opt
                    );
                    return false;
                } else {
                    key_nonduplicable_opts.insert(nonduplicable_opt, key_opt.clone());
                }
            }
        }
        return true;
    });

    let mut opts_tokens = [key_opts_tokens, user_opts_tokens, source_opts_tokens]
        .concat();

    opts_tokens.retain(|o| !o.is_empty());
    let combined_opts = opts_tokens.join(",");

    if let Some(marker) = marker_option {
        [marker, combined_opts].join(" ")
    } else {
        combined_opts
    }
}

// Processes a line of the user's key definitions file
// If there exists a cached response and it is fresher than cache_stale seconds, print it, return Ok(Some(cached response)), and omit making the request
// If there exists a cached response but it is staler than cache_stale seconds, dump the cached response into cached_output, and proceed to making the request
// If response code is not 200, then return Ok(None)
// If request is successful, then write the response to the cache and return Ok(Some(response))
// If any other error occurs, return Err()
fn process_user_def_line<T, U>(
    user: &User,
    (
        (source_name, (source_url, source_opts)),
        user_line_tokens,
        user_opts
    ): (
        (String, (String, Option<String>)),
        Vec<String>,
        Option<String>
    ),
    cache_directory: &Path,
    cached_output: &mut Vec<String>,
    cache_stale: u64,
    request_timeout: u64,
    http_client_trait: &T,
    fs_trait: &U,
) -> Result<Option<String>>
where
    T: HttpClientTrait,
    U: FsTrait,
{
    let cache_path = get_cache_filename(
        &source_name, &user_line_tokens, cache_directory
    );

    info!("Looking for a cached response at {:?}", cache_path);
    match ensure_safe_permissions_and_read(&cache_path, Some(user), fs_trait).and_then(
        |(cached_string, metadata)| {
            is_cache_fresh(metadata, cache_stale)
                .map(|is_cache_fresh_bool| (is_cache_fresh_bool, cached_string))
        },
    ) {
        Ok((is_cache_fresh_bool, cached_string)) => {
            let (cached_key_opts, cached_key_line) = parse_key_line(&cached_string);
            let cached_key_combined_opts = combine_opts(cached_key_opts, user_opts.clone(), source_opts.clone());
            let combined_opts_key_line = if cached_key_combined_opts.is_empty() {
                cached_string
            } else {
                [cached_key_combined_opts, cached_key_line].join(" ")
            };

            if is_cache_fresh_bool {
                info!("Found fresh cached response. Omitting request");
                return Ok(Some(combined_opts_key_line));
            } else {
                info!("Cache is stale. Proceeding to make request");
                cached_output.push(combined_opts_key_line);
            }
        }
        Err(e) => {
            info!(
                "{:?}",
                e.context("Didn't find a usable cache. Proceeding to make request")
            );
        }
    }

    let url =
        construct_url(&source_url,&user_line_tokens)
        .context("Couldn't construct request URL")?;

    let response_string = http_client_trait
        .request_from_url(url, request_timeout)
        .context("Request was unsuccessful")?;

    if let Err(e) = write_to_cache(cache_path, &response_string, fs_trait) {
        warn!("{:?}", e.context("Couldn't write to cache"));
    }

    let (response_key_opts, response_key_line) = parse_key_line(&response_string);

    let response_key_combined_opts = combine_opts(response_key_opts, user_opts, source_opts);

    Ok(Some(
        if response_key_combined_opts.is_empty() {
            response_string
        } else {
            [response_key_combined_opts, response_key_line].join(" ")
        }
    ))
}

// Returns true if the given key, if Some, is present in the given response string
fn is_key_in_response_str(key_to_find_option: Option<&str>, response_str: String) -> bool {
    match key_to_find_option {
        Some(key_to_find) => response_str.lines().any(|line| line.contains(key_to_find)),
        None => false,
    }
}

#[cfg_attr(test, automock)]
trait PrintTrait {
    fn print(&self, s: &str);
}

struct StdOut;

impl PrintTrait for StdOut {
    fn print(&self, s: &str) {
        print!("{}", s);
    }
}

// Parse and process a user definitions string
fn process_user_defs<T, U, V>(
    user: &User,
    source_defs_map: &HashMap<String, (String, Option<String>)>,
    cache_directory: &Path,
    user_defs_string: &str,
    key_to_find: Option<&str>,
    cache_stale: u64,
    request_timeout: u64,
    http_client_trait: &T,
    fs_trait: &U,
    print_trait: &V,
) -> Result<()>
where
    T: HttpClientTrait,
    U: FsTrait,
    V: PrintTrait,
{
    let mut cached_output: Vec<String> = Vec::new();

    let mut some_line_output = false;

    for (line_number, user_defs_line) in user_defs_string.lines().into_iter().enumerate() {
        if let Some(parsed_line) = parse_user_def_line(user_defs_line, source_defs_map)? {
            info!("Found source {} for user definition line {}", parsed_line.0.0, user_defs_line);

            match process_user_def_line(
                user,
                parsed_line,
                cache_directory,
                &mut cached_output,
                cache_stale,
                request_timeout,
                http_client_trait,
                fs_trait,
            ) {
                Ok(Some(line_retrieved_response)) => {
                    // If there was no error processing this line, and there exists a fresh cache or the response code is 200 for this line ...
                    some_line_output = true;
                    print_trait.print(&line_retrieved_response);
                    if is_key_in_response_str(key_to_find, line_retrieved_response) {
                        // ... and the key_to_find (if Some) is found, then skip subsequent lines
                        info!(
                            "Found the provided key when processing line {}. Skipping subsequent lines",
                            line_number + 1
                        );
                        break;
                    }
                }
                Ok(None) => {}
                Err(line_err) => {
                    // If there was an error processing this line, skip it
                    warn!(
                        "{:?}",
                        line_err.context(format!("Skipping line {}", line_number + 1))
                    );
                }
            }
        }
    }
    if !some_line_output {
        // For all lines, if
        // either there does not exist a fresh cache and the response code is not 200,
        // or there was an error processing the line,
        // then print all stale caches that exist
        warn!("None of the source definitions provided a recent cached response or a successful request");

        if cached_output.len() == 0 {
            warn!("No usable stale caches were found");
        } else {
            warn!("Using stale caches");
            for cached_output_entry in cached_output {
                print_trait.print(&cached_output_entry);
            }
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Username for which to fetch keys. If not specified, defaults to the user that owns this process. When specifying this program for the AuthorizedKeysCommand in sshd_config, use the token %u, which sshd will substitute with the username of the user who is requesting to authenticate
    username: Option<String>,

    /// Key to look for (will stop once found). Optional. When specifying this program for the AuthorizedKeysCommand in sshd_config, use the token %k, which sshd will substitute with the public key sent by the client
    key: Option<String>,

    /// Override user definition string. Takes precedence over --user-defs
    #[arg(short='U', long="override-user-def")]
    override_user_def: Option<String>,

    /// User definitions file path. Defaults to ~<username>/.ssh/fetch_keys
    #[arg(short='u', long="user-defs")]
    user_defs: Option<String>,

    /// Override source definition string. Takes precedence over --source-defs
    #[arg(short='S', long="override-source-def")]
    override_source_def: Option<String>,

    /// Source definitions file path. Defaults to /etc/ssh/fetch_keys.conf
    #[arg(short='s', long="source-defs")]
    source_defs: Option<String>,

    /// Cache directory path. Defaults to ~<username>/.ssh/fetch_keys.d/
    #[arg(short='c', long="cache-directory")]
    cache_directory: Option<String>,

    /// Skip making a new request to a source if it has been less than this many seconds since that source's cache was last modified. 0 to ignore any caches
    #[arg(long="cache-stale", default_value_t=60)]
    cache_stale: u64,

    /// Timeout for requests in seconds
    #[arg(long="request-timeout", default_value_t=5)]
    request_timeout: u64,

    #[clap(flatten)]
    verbose: clap_verbosity_flag::Verbosity,
}

fn fetch_print_keys<T, U, V, W, X, Y>(
    args: Args,
    users_table: &T,
    switch_user_trait: &U,
    http_client_trait: &W,
    fs_trait: &X,
    print_trait: &Y,
) -> Result<()>
where
    T: Users,
    U: SwitchUserTrait<V>,
    V: SwitchUserGuardTrait,
    W: HttpClientTrait,
    X: FsTrait,
    Y: PrintTrait,
{
    let (user, guard) = switch_user(args.username.as_deref(), users_table, switch_user_trait)?;

    process_user_defs(
        &user,
        &{
            match args.override_source_def {
                Some(override_source_def) => get_source_defs(&override_source_def),
                None => {
                    let (source_defs_path, user_option) = match args.source_defs {
                        Some(override_path) => (PathBuf::from(override_path), None),
                        None => (
                            PathBuf::from("/etc/ssh/fetch_keys.conf"),
                            Some(
                                users_table
                                    .get_user_by_uid(0)
                                    .context("Couldn't get root user")?
                                    .as_ref()
                                    .clone(),
                            ),
                        ),
                    };
                    info!("Looking for source definitions at {:?}", source_defs_path);
                    get_source_defs(
                        &ensure_safe_permissions_and_read(
                            &source_defs_path,
                            user_option.as_ref(),
                            fs_trait,
                        )?
                        .0,
                    )
                }
            }
        }?,
        &match args.cache_directory {
            Some(override_path) => PathBuf::from(override_path),
            None => user.home_dir().join(".ssh/fetch_keys.d"),
        },
        &{
            match args.override_user_def {
                Some(override_user_def) => override_user_def,
                None => {
                    let (user_defs_path, user_option) = match args.user_defs {
                        Some(override_path) => (PathBuf::from(override_path), None),
                        None => (user.home_dir().join(".ssh/fetch_keys"), Some(&user)),
                    };
                    info!("Looking for user definitions at {:?}", user_defs_path);
                    ensure_safe_permissions_and_read(&user_defs_path, user_option, fs_trait)?
                        .0
                }
            }
        },
        args.key.as_deref(),
        args.cache_stale,
        args.request_timeout,
        http_client_trait,
        fs_trait,
        print_trait,
    )?;

    // Switch user back
    if let Some(b) = guard {
        b.drop_trait();
    }

    Ok(())
}

fn main() {
    let args = Args::parse();

    // Set log level
    Builder::from_default_env()
        .filter_level(args.verbose.log_level_filter())
        .init();

    if let Err(e) = fetch_print_keys(
        args,
        &mut UsersCache::new(),
        &SwitchUser {},
        {
            #[cfg(feature = "curl")]
            { &CurlHttpClient {} }
            #[cfg(feature = "reqwest")]
            { &ReqwestHttpClient {} }
        },
        &StdFs {},
        &StdOut {},
    ) {
        error!("{:?}", e.context("Exiting"));
        process::exit(1);
    };
}

#[cfg(test)]
mod tests_switch_user {
    use super::*;
    use uzers::mock::MockUsers;

    fn prepare_switch_user_test(
        user_name_option: Option<&str>,
        expect_switch_user_call: bool,
    ) -> Result<(User, Option<MockSwitchUserGuardTrait>)> {
        let mut mock_switch_user: MockSwitchUserTrait<MockSwitchUserGuardTrait> =
            MockSwitchUserTrait::new();
        let expected_switch_user_guard: MockSwitchUserGuardTrait =
            MockSwitchUserGuardTrait::new();

        let expected_user_uid = 1000;
        let expected_user_gid = 1000;
        let expected_user_name = "test_user";
        let expected_user = User::new(expected_user_uid, expected_user_name, expected_user_gid);

        let current_user_uid = 1001;
        let current_user_gid = 1001;
        let current_user_name = "current_user";
        let current_user = User::new(current_user_uid, current_user_name, current_user_gid);

        mock_switch_user
            .expect_switch_user_group()
            .withf(move |uid, gid| *uid == expected_user_uid && *gid == expected_user_gid)
            .return_once_st(|_, _| Ok(expected_switch_user_guard))
            .times(match expect_switch_user_call {
                true => 1,
                false => 0,
            });

        let mut user_table = MockUsers::with_current_uid(current_user_uid);
        user_table.add_user(expected_user);
        user_table.add_user(current_user);

        switch_user(user_name_option, &mut user_table, &mock_switch_user)
    }

    #[test_log::test]
    fn test_some_user_name() {
        let (actual_user, expected_switch_user_guard_option) =
            prepare_switch_user_test(Some("test_user"), true).unwrap();

        assert_eq!(actual_user.name(), "test_user");
        assert_eq!(actual_user.uid(), 1000);
        assert_eq!(actual_user.primary_group_id(), 1000);

        assert!(expected_switch_user_guard_option.is_some());
    }

    #[test_log::test]
    fn test_none_user_name() {
        let (actual_user, expected_switch_user_guard_option) =
            prepare_switch_user_test(None, false).unwrap();

        assert_eq!(actual_user.name(), "current_user");
        assert_eq!(actual_user.uid(), 1001);
        assert_eq!(actual_user.primary_group_id(), 1001);

        assert!(expected_switch_user_guard_option.is_none());
    }

    #[test_log::test]
    fn test_bogus_user_name() {
        assert!(prepare_switch_user_test(Some("bogus_user"), false).is_err());
    }
}

#[cfg(test)]
mod tests_ensure_safe_permissions_and_read {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test_log::test]
    fn test_nonexistent() {
        let mut mock_fs = MockFsTrait::new();
        let path = Path::new("/home/user/.ssh/fetch_keys");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        assert!(
            ensure_safe_permissions_and_read(&path, Some(&User::new(0, "", 0)), &mock_fs).is_err()
        );
    }

    #[test_log::test]
    fn test_not_owned_by_user() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let path = Path::new("/home/user/.ssh/fetch_keys");
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        assert!(
            ensure_safe_permissions_and_read(&path, Some(&User::new(0, "", 0)), &mock_fs).is_err()
        );
    }

    #[test_log::test]
    fn test_bad_permissions() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let path = Path::new("/home/user/.ssh/fetch_keys");
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o666u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        assert!(
            ensure_safe_permissions_and_read(&path, Some(&User::new(1000, "", 0)), &mock_fs)
                .is_err()
        );
    }

    #[test_log::test]
    fn test_read_to_string() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let path = Path::new("/home/user/.ssh/fetch_keys");
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(2);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(2);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(path))
            .return_once_st(|_| Ok("test string".to_string()))
            .times(1);
        let (actual_string, actual_metadata) =
            ensure_safe_permissions_and_read(&path, Some(&User::new(1000, "", 0)), &mock_fs)
                .unwrap();
        assert_eq!(actual_string, "test string");
        assert_eq!(actual_metadata.uid_trait(), 1000u32);
        assert_eq!(actual_metadata.mode_trait(), 0o600u32);
    }
}

#[cfg(test)]
mod tests_get_source_defs {
    use super::*;

    fn prepare_get_source_defs_test(
        source_defs_string: &str,
        expected_result_vec_pairs: Option<Vec<(&str, (&str, Option<&str>))>>,
    ) {
        let actual_source_defs_map_result = get_source_defs(source_defs_string);

        match actual_source_defs_map_result {
            Ok(actual_source_defs_map) => {
                assert_eq!(
                    actual_source_defs_map,
                    expected_result_vec_pairs
                        .unwrap()
                        .into_iter()
                        .map(|(a, (b, c))| (a.to_string(), (b.to_string(), c.map(str::to_string))))
                        .collect()
                );
            }
            Err(_) => {
                assert!(expected_result_vec_pairs.is_none());
            }
        }
    }

    #[test_log::test]
    fn test_empty_string() {
        prepare_get_source_defs_test("", None);
    }

    #[test_log::test]
    fn test_empty_line_skipped() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}1\n\n2 https://example.com/{}2",
            Some(vec![
                ("1", ("https://example.com/{}1", None)),
                ("2", ("https://example.com/{}2", None))
            ])
        );
    }

    #[test_log::test]
    fn test_comment_line_skipped() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}\n# comment\n # comment\n#comment",
            Some(vec![("1", ("https://example.com/{}", None))])
        );
    }

    #[test_log::test]
    fn test_one_token_skipped() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}\n3",
            Some(vec![("1", ("https://example.com/{}", None))])
        );
    }

    #[test_log::test]
    fn test_two_tokens() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", None))])
        );
    }

    #[test_log::test]
    fn test_extra_spaces() {
        prepare_get_source_defs_test(
            "1   https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", None))])
        );
    }

    #[test_log::test]
    fn test_two_lines() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}1\n2 https://example.com/{}2",
            Some(vec![
                ("1", ("https://example.com/{}1", None)),
                ("2", ("https://example.com/{}2", None))
            ])
        );
    }

    #[test_log::test]
    fn test_duplicate_source_definition() {
        prepare_get_source_defs_test(
            "1 https://example.com/{}1\n\n1 https://example.com/{}2",
            Some(vec![("1", ("https://example.com/{}2", None))])
        );
    }

    #[test_log::test]
    fn test_three_tokens_third_is_url() {
        prepare_get_source_defs_test(
            "option 1 https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", Some("option")))])
        );
    }

    #[test_log::test]
    fn test_three_tokens_third_is_url_first_has_quotes() {
        prepare_get_source_defs_test(
            "option\"abc\" 1 https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", Some("option\"abc\"")))])
        );
    }

    #[test_log::test]
    fn test_three_tokens_third_is_url_first_has_spaces_in_quotes() {
        prepare_get_source_defs_test(
            "option\"ab c\" 1 https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", Some("option\"ab c\"")))])
        );
    }

    #[test_log::test]
    fn test_three_tokens_third_is_url_first_has_escaped_quotes_in_quotes() {
        prepare_get_source_defs_test(
            "option\"ab\\\"c\" 1 https://example.com/{}",
            Some(vec![("1", ("https://example.com/{}", Some("option\"ab\\\"c\"")))])
        );
    }

    #[test_log::test]
    fn test_three_tokens_third_is_not_url() {
        prepare_get_source_defs_test(
            "1 https://example.com/{} 2",
            Some(vec![("1", ("https://example.com/{}", None))])
        );
    }
}

#[cfg(test)]
mod tests_get_cache_filename {
    use super::*;

    fn prepare_get_cache_filename_test(
        source_name: &str,
        line_tokens: Vec<&str>,
        cache_directory: &str,
        expected_result: &str,
    ) {
        assert_eq!(
            get_cache_filename(
                source_name,
                &line_tokens
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<String>>(),
                Path::new(cache_directory)
            ),
            PathBuf::from(expected_result)
        );
    }

    #[test_log::test]
    fn test_one_token() {
        prepare_get_cache_filename_test("1", vec![], "/tmp", "/tmp/83dcefb7-1");
    }

    #[test_log::test]
    fn test_two_tokens() {
        prepare_get_cache_filename_test("1", vec!["2"], "/tmp", "/tmp/87bb2397-1_2");
    }

    #[test_log::test]
    fn test_three_tokens() {
        prepare_get_cache_filename_test("1", vec!["2", "3"], "/tmp", "/tmp/f7eabd5f-1_2_3");
    }

    #[test_log::test]
    fn test_allowed_nonalphanumeric_character() {
        prepare_get_cache_filename_test("1-2", vec![], "/tmp", "/tmp/32155dda-1-2");
    }

    #[test_log::test]
    fn test_forbidden_nonalphanumeric_character() {
        prepare_get_cache_filename_test("1*2", vec![], "/tmp", "/tmp/7d54cb1d-1-2");
    }

    #[test_log::test]
    fn test_directory() {
        prepare_get_cache_filename_test("1*2", vec![], "/tmp/test", "/tmp/test/7d54cb1d-1-2");
    }
}

#[cfg(test)]
mod tests_is_cache_fresh {
    use super::*;
    use anyhow::anyhow;

    #[test_log::test]
    fn test_err() {
        let mut mock_metadata = MockMetadataTrait::new();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| Err(anyhow!("")))
            .times(1);
        assert!(is_cache_fresh(Box::new(mock_metadata), 0).is_err());
    }

    #[test_log::test]
    fn test_stale_ok_false() {
        let mut mock_metadata = MockMetadataTrait::new();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(60))
                    .unwrap())
            })
            .times(1);
        assert!(!is_cache_fresh(Box::new(mock_metadata), 1).unwrap());
    }

    #[test_log::test]
    fn test_fresh_ok_true() {
        let mut mock_metadata = MockMetadataTrait::new();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(1))
                    .unwrap())
            })
            .times(1);
        assert!(is_cache_fresh(Box::new(mock_metadata), 60).unwrap());
    }
}

#[cfg(test)]
mod tests_construct_url {
    use super::*;
    use anyhow::anyhow;

    fn prepare_construct_url_test(
        url_template: &str,
        line_tokens: Vec<&str>,
        expected_result_url: Result<&str>,
    ) {
        match construct_url(url_template, &line_tokens) {
            Ok(actual_construct_url) => {
                assert_eq!(actual_construct_url, expected_result_url.unwrap());
            }
            Err(_) => {
                assert!(expected_result_url.is_err());
            }
        }
    }

    #[test_log::test]
    fn test_correct_parameters() {
        prepare_construct_url_test("z{1}{2}", vec!["a", "b"], Ok("zab"));
    }

    #[test_log::test]
    fn test_too_few_parameters() {
        prepare_construct_url_test("z{1}{2}", vec!["a"], Err(anyhow!("")));
    }

    #[test_log::test]
    fn test_too_many_parameters() {
        prepare_construct_url_test("z{1}{2}", vec!["a", "b", "c"], Ok("zab"));
    }
}

#[cfg(test)]
mod tests_write_to_cache {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test_log::test]
    fn test_bad_cache_path_parent() {
        assert!(write_to_cache(PathBuf::from("/"), "", &MockFsTrait::new()).is_err());
    }

    #[test_log::test]
    fn test_cache_dir_exists() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_metadata
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(|_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(|_, _| Ok(()))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_ok());
    }

    #[test_log::test]
    fn test_cache_exists_not_a_dir() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_metadata
            .expect_is_dir_trait()
            .return_const(false)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_err());
    }

    #[test_log::test]
    fn test_cache_dir_does_not_exist() {
        let mut mock_fs = MockFsTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_fs
            .expect_create_dir_all()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Ok(()))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(|_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(|_, _| Ok(()))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_ok());
    }

    #[test_log::test]
    fn test_cache_dir_does_not_exist_could_not_create() {
        let mut mock_fs = MockFsTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_fs
            .expect_create_dir_all()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_err());
    }

    #[test_log::test]
    fn test_cache_dir_could_not_write() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_metadata
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(|_, _| Err(anyhow!("")))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_err());
    }

    #[test_log::test]
    fn test_could_not_set_permissions() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/test");
        let response_str = "a";
        let expected_path_parent = Path::new("/home/user/.ssh/fetch_keys.d/");
        mock_metadata
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_path_parent))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(|_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(|_, _| Err(anyhow!("")))
            .times(1);
        assert!(write_to_cache(cache_path.to_path_buf(), response_str, &mock_fs).is_err());
    }
}

#[cfg(test)]
mod tests_parse_user_def_line {
    use super::*;

    fn prepare_parse_user_def_line_test(
        user_defs_line: &str,
        source_defs_map: Vec<(&str, (&str, Option<&str>))>,
        expected_result: Option<Option<(
            (&str, (&str, Option<&str>)),
            Vec<&str>,
            Option<&str>
        )>>
    ) {
        let actual_parse_user_def_line_result = parse_user_def_line(
            user_defs_line,
            &source_defs_map
                .into_iter()
                .map(|(a, (b, c))| (a.to_string(), (b.to_string(), c.map(str::to_string))))
                .collect()
        );

        match actual_parse_user_def_line_result {
            Ok(actual_parse_user_def_line) => {
                assert_eq!(
                    actual_parse_user_def_line,
                    expected_result
                        .unwrap()
                        .map(|((a, (b, c)), d, e)|
                            (
                                (a.to_string(), (b.to_string(), c.map(str::to_string))),
                                d.into_iter().map(str::to_string).collect(),
                                e.map(str::to_string)
                            )
                        )
                );
            }
            Err(_) => {
                assert!(expected_result.is_none());
            }
        }
    }

    #[test_log::test]
    fn test_empty_string() {
        prepare_parse_user_def_line_test("", vec![], Some(None));
    }

    #[test_log::test]
    fn test_comment_line_skipped_1() {
        prepare_parse_user_def_line_test(
            "# comment", vec![], Some(None)
        );
    }

    #[test_log::test]
    fn test_comment_line_skipped_2() {
        prepare_parse_user_def_line_test(
            " # comment", vec![], Some(None)
        );
    }

    #[test_log::test]
    fn test_comment_line_skipped_3() {
        prepare_parse_user_def_line_test(
            "#comment", vec![], Some(None)
        );
    }

    #[test_log::test]
    fn test_second_token_is_in_map() {
        prepare_parse_user_def_line_test(
            "user-option 1 2 3",
            vec![("1", ("{1}", Some("source-option")))],
            Some(Some((("1", ("{1}", Some("source-option"))), vec!["2", "3"], Some("user-option"))))
        );
    }

    #[test_log::test]
    fn test_second_token_not_in_map_first_token_is_in_map() {
        prepare_parse_user_def_line_test(
            "1 2 3",
            vec![("1", ("{1}", Some("source-option")))],
            Some(Some((("1", ("{1}", Some("source-option"))), vec!["2", "3"], None)))
        );
    }

    #[test_log::test]
    fn test_second_token_not_in_map_first_token_not_in_map() {
        prepare_parse_user_def_line_test(
            "2 3 4",
            vec![("1", ("{1}", Some("source-option")))],
            None
        );
    }
}

#[cfg(test)]
mod tests_parse_key_line_test {
    use super::*;

    fn prepare_key_line_test(
        key_line: &str,
        expected: (Option<&str>, &str)
    ) {
        assert_eq!(
            parse_key_line(key_line),
            (expected.0.map(str::to_string), expected.1.to_string())
        );
    }

    #[test_log::test]
    fn test_empty_string() {
        prepare_key_line_test("", (None, ""));
    }

    #[test_log::test]
    fn test_comment_string_1() {
        prepare_key_line_test("# comment", (None, "# comment"));
    }

    #[test_log::test]
    fn test_comment_string_2() {
        prepare_key_line_test(" # comment", (None, " # comment"));
    }

    #[test_log::test]
    fn test_comment_string_3() {
        prepare_key_line_test("#comment", (None, "#comment"));
    }

    #[test_log::test]
    fn test_one_token() {
        prepare_key_line_test("a", (None, "a"));
    }

    #[test_log::test]
    fn test_two_tokens_unknown_key_type() {
        prepare_key_line_test("a b", (None, "a b"));
    }

    #[test_log::test]
    fn test_two_tokens_known_key_type() {
        prepare_key_line_test("a ssh-rsa", (Some("a"), "ssh-rsa"));
    }

    #[test_log::test]
    fn test_three_tokens_known_key_type() {
        prepare_key_line_test("a ssh-rsa b", (Some("a"), "ssh-rsa b"));
    }
}

#[cfg(test)]
mod tests_split_at_first_marker {
    use super::*;

    fn prepare_split_at_first_marker_test(
        opts_option: Option<&str>,
        expected: (Option<&str>, Option<&str>)
    ) {
        assert_eq!(
            split_at_first_marker(
                opts_option.map(|opts| opts.to_string())
            ),
            (
                expected.0.map(|marker| marker.to_string()),
                expected.1.map(|opts| opts.to_string())
            )
        );
    }

    #[test_log::test]
    fn test_none() {
        prepare_split_at_first_marker_test(None, (None, None));
    }

    #[test_log::test]
    fn test_no_marker_no_opts() {
        prepare_split_at_first_marker_test(None, (None, None));
    }

    #[test_log::test]
    fn test_no_marker_with_opts() {
        prepare_split_at_first_marker_test(Some("x y z"), (None, Some("x y z")));
    }

    #[test_log::test]
    fn test_one_marker_no_opts() {
        prepare_split_at_first_marker_test(Some("@x"), (Some("@x"), None));
    }

    #[test_log::test]
    fn test_one_marker_with_opts() {
        prepare_split_at_first_marker_test(Some("@x y z"), (Some("@x"), Some("y z")));
    }

    #[test_log::test]
    fn test_two_markers_with_opts() {
        prepare_split_at_first_marker_test(Some("@x @y z"), (Some("@x"), Some("@y z")));
    }
}

#[cfg(test)]
mod tests_combine_and_strip_markers {
    use super::*;

    fn prepare_combine_and_strip_markers_test(
        key_opts_option: Option<&str>,
        user_opts_option: Option<&str>,
        source_opts_option: Option<&str>,
        expected: (
            Option<&str>,
            Option<&str>,
            Option<&str>,
            Option<&str>
        )
    ) {
        assert_eq!(
            combine_and_strip_markers(
                key_opts_option.map(|opts| opts.to_string()),
                user_opts_option.map(|opts| opts.to_string()),
                source_opts_option.map(|opts| opts.to_string())
            ),
            (
                expected.0.map(|marker| marker.to_string()),
                expected.1.map(|opts| opts.to_string()),
                expected.2.map(|opts| opts.to_string()),
                expected.3.map(|opts| opts.to_string())
            )
        );
    }

    #[test_log::test]
    fn test_none_none_none() {
        prepare_combine_and_strip_markers_test(
            None,
            None,
            None,
            (None, None, None, None)
        );
    }

    #[test_log::test]
    fn test_revoked_none_none() {
        prepare_combine_and_strip_markers_test(
            Some("@revoked"),
            None,
            None,
            (Some("@revoked"), None, None, None)
        );
    }

    #[test_log::test]
    fn test_none_ca_none() {
        prepare_combine_and_strip_markers_test(
            None,
            Some("@cert-authority"),
            None,
            (Some("@cert-authority"), None, None, None)
        );
    }

    #[test_log::test]
    fn test_revoked_ca_none() {
        prepare_combine_and_strip_markers_test(
            Some("@revoked"),
            Some("@cert-authority"),
            None,
            (Some("@revoked"), None, None, None)
        );
    }

    #[test_log::test]
    fn test_revoked_ca_opt_none() {
        prepare_combine_and_strip_markers_test(
            Some("@revoked"),
            Some("@cert-authority x"),
            None,
            (Some("@revoked"), None, Some("x"), None)
        );
    }

    #[test_log::test]
    fn test_opt_ca_opt_revoked_opt() {
        prepare_combine_and_strip_markers_test(
            Some("x"),
            Some("@cert-authority y"),
            Some("@revoked z"),
            (Some("@revoked"), Some("x"), Some("y"), Some("z"))
        );
    }
}

#[cfg(test)]
mod tests_combine_opts {
    use super::*;

    fn prepare_combine_opts_test(
        key_opts: Option<&str>,
        user_opts: Option<&str>,
        source_opts: Option<&str>,
        expected: &str
    ) {
        assert_eq!(
            combine_opts(
                key_opts.map(|a| a.to_string()),
                user_opts.map(|b| b.to_string()),
                source_opts.map(|c| c.to_string())
            ),
            expected.to_string()
        );
    }

    #[test_log::test]
    fn test_no_opts() {
        prepare_combine_opts_test(None, None, None, "");
    }

    #[test_log::test]
    fn test_source_opts_only() {
        prepare_combine_opts_test(None, None, Some("a"), "a");
    }

    #[test_log::test]
    fn test_user_opts_only() {
        prepare_combine_opts_test(None, Some("a"), None, "a");
    }

    #[test_log::test]
    fn test_key_opts_only() {
        prepare_combine_opts_test(Some("a"), None, None, "a");
    }

    #[test_log::test]
    fn test_source_user_opts_no_conflict() {
        prepare_combine_opts_test(None, Some("a"), Some("a"), "a,a");
    }

    #[test_log::test]
    fn test_user_key_opts_no_conflict() {
        prepare_combine_opts_test(Some("a"), Some("a"), None, "a,a");
    }

    #[test_log::test]
    fn test_source_key_opts_no_conflict() {
        prepare_combine_opts_test(Some("a"), None, Some("a"), "a,a");
    }

    #[test_log::test]
    fn test_source_user_key_opts_no_conflict() {
        prepare_combine_opts_test(Some("a"), Some("a"), Some("a"), "a,a,a");
    }

    #[test_log::test]
    fn test_opts_no_conflict() {
        prepare_combine_opts_test(Some("from=\"1\""), Some("command=\"2\""), Some("principals=\"3\""), "from=\"1\",command=\"2\",principals=\"3\"");
    }

    #[test_log::test]
    fn test_source_user_opts_conflict() {
        prepare_combine_opts_test(None, Some("command=\"1\""), Some("command=\"2\""), "command=\"2\"");
    }

    #[test_log::test]
    fn test_user_key_opts_conflict() {
        prepare_combine_opts_test(Some("command=\"1\""), Some("command=\"2\""), None, "command=\"2\"");
    }

    #[test_log::test]
    fn test_source_key_opts_conflict() {
        prepare_combine_opts_test(Some("command=\"1\""), None, Some("command=\"2\""), "command=\"2\"");
    }

    #[test_log::test]
    fn test_source_user_key_opts_conflict() {
        prepare_combine_opts_test(Some("command=\"1\""), Some("command=\"2\""), Some("command=\"3\""), "command=\"3\"");
    }

    #[test_log::test]
    fn test_one_marker() {
        prepare_combine_opts_test(Some("@revoked x"), Some("y"), Some("z"), "@revoked x,y,z");
    }

    #[test_log::test]
    fn test_two_markers() {
        prepare_combine_opts_test(Some("@revoked x"), Some("@cert-authority y"), Some("z"), "@revoked x,y,z");
    }
}

#[cfg(test)]
mod tests_process_user_def_line {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test_log::test]
    fn test_fresh_cache() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(1))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            60,
            0,
            &MockHttpClientTrait::new(),
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, response_str);
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_fresh_cache_opts() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "command=\"key\" ssh-rsa z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(1))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (
                ("1".to_string(), ("{1}".to_string(), Some("command=\"source\"".to_string()))),
                vec!["2".to_string()],
                Some("command=\"user\"".to_string())
            ),
            cache_directory,
            &mut actual_cache_vec,
            60,
            0,
            &MockHttpClientTrait::new(),
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, "command=\"source\" ssh-rsa z");
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_stale_cache() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let mut mock_metadata_parent = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(60))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);
        mock_metadata_parent
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory))
            .return_once_st(|_| Ok(Box::new(mock_metadata_parent)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, response_str);
        assert_eq!(actual_cache_vec.len(), 1);
        assert_eq!(actual_cache_vec[0], response_str);
    }

    #[test_log::test]
    fn test_stale_cache_opts() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let mut mock_metadata_parent = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "command=\"key\" ssh-rsa z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(60))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);
        mock_metadata_parent
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory))
            .return_once_st(|_| Ok(Box::new(mock_metadata_parent)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (
                ("1".to_string(), ("{1}".to_string(), Some("command=\"source\"".to_string()))),
                vec!["2".to_string()],
                Some("command=\"user\"".to_string())
            ),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, "command=\"source\" ssh-rsa z");
        assert_eq!(actual_cache_vec.len(), 1);
        assert_eq!(actual_cache_vec[0], "command=\"source\" ssh-rsa z");
    }

    #[test_log::test]
    fn test_no_cache() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata_parent = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let response_str = "z";
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = Path::new("/home/user/.ssh/fetch_keys.d");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);
        mock_metadata_parent
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory))
            .return_once_st(|_| Ok(Box::new(mock_metadata_parent)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, response_str);
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_no_cache_opts() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata_parent = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let response_str = "command=\"key\" ssh-rsa z";
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = Path::new("/home/user/.ssh/fetch_keys.d");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);
        mock_metadata_parent
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory))
            .return_once_st(|_| Ok(Box::new(mock_metadata_parent)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (
                ("1".to_string(), ("{1}".to_string(), Some("command=\"source\"".to_string()))),
                vec!["2".to_string()],
                Some("command=\"user\"".to_string())
            ),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, "command=\"source\" ssh-rsa z");
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_construct_url_failed() {
        let mut mock_fs = MockFsTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = Path::new("/home/user/.ssh/fetch_keys.d");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        // Not enough parameters
        assert!(process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1} {2}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &MockHttpClientTrait::new(),
            &mock_fs,
        )
        .is_err());
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_request_from_url_failed() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = Path::new("/home/user/.ssh/fetch_keys.d");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Err(anyhow!("")))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        assert!(process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .is_err());
        assert_eq!(actual_cache_vec.len(), 0);
    }

    #[test_log::test]
    fn test_write_to_cache_failed() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata_parent = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let response_str = "z";
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = Path::new("/home/user/.ssh/fetch_keys.d");
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);
        mock_metadata_parent
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory))
            .return_once_st(|_| Ok(Box::new(mock_metadata_parent)))
            .times(1);
        mock_fs
            .expect_write()
            .with(predicate::eq(cache_path), predicate::eq(response_str))
            .return_once_st(move |_, _| Err(anyhow!("")))
            .times(1);

        let mut actual_cache_vec: Vec<String> = vec![];

        let actual_string = process_user_def_line(
            &User::new(1000u32, "", 0),
            (("1".to_string(), ("{1}".to_string(), None)), vec!["2".to_string()], None),
            cache_directory,
            &mut actual_cache_vec,
            1,
            1,
            &mock_http_client,
            &mock_fs,
        )
        .unwrap()
        .unwrap();

        assert_eq!(actual_string, response_str);
        assert_eq!(actual_cache_vec.len(), 0);
    }
}

#[cfg(test)]
mod tests_is_key_in_response_str {
    use super::*;

    #[test_log::test]
    fn none() {
        assert!(!is_key_in_response_str(None, "".to_string()));
    }

    #[test_log::test]
    fn some_no() {
        assert!(!is_key_in_response_str(Some("a"), "b\nc".to_string()));
    }

    #[test_log::test]
    fn some_yes_end() {
        assert!(is_key_in_response_str(Some("a"), "b\na".to_string()));
    }

    #[test_log::test]
    fn some_yes_middle() {
        assert!(is_key_in_response_str(Some("b"), "ab\nc".to_string()));
    }
}

#[cfg(test)]
mod tests_process_user_defs {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test_log::test]
    fn found() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let mut mock_print = MockPrintTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(1))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);

        mock_print
            .expect_print()
            .with(predicate::eq(response_str))
            .return_const(())
            .times(1);

        let mut source_defs = HashMap::new();
        source_defs.insert("1".to_string(), ("{1}".to_string(), None));

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            &source_defs,
            cache_directory,
            "1 2\n3 4",
            Some(response_str),
            60,
            0,
            &MockHttpClientTrait::new(),
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }

    #[test_log::test]
    fn only_stale() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_metadata = MockMetadataTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let mut mock_print = MockPrintTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let response_str = "z";
        let cache_directory = cache_path.parent().unwrap();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| {
                Ok(time::SystemTime::now()
                    .checked_sub(time::Duration::from_secs(60))
                    .unwrap())
            })
            .times(1);
        mock_metadata
            .expect_uid_trait()
            .return_const(1000u32)
            .times(1);
        mock_metadata
            .expect_mode_trait()
            .return_const(0o600u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(cache_path))
            .return_once_st(move |_| Ok(response_str.to_string()))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Err(anyhow!("")))
            .times(1);

        mock_print
            .expect_print()
            .with(predicate::eq(response_str))
            .return_const(())
            .times(1);

        let mut source_defs = HashMap::new();
        source_defs.insert("1".to_string(), ("{1}".to_string(), None));

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            &source_defs,
            cache_directory,
            "1 2\n# comment",
            None,
            1,
            1,
            &mock_http_client,
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }

    #[test_log::test]
    fn err() {
        let mut mock_fs = MockFsTrait::new();
        let mut mock_http_client = MockHttpClientTrait::new();
        let cache_path = Path::new("/home/user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory = cache_path.parent().unwrap();
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(1))
            .return_once_st(move |_, _| Err(anyhow!("")))
            .times(1);

        let mut source_defs = HashMap::new();
        source_defs.insert("1".to_string(), ("{1}".to_string(), None));

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            &source_defs,
            cache_directory,
            "1 2\n# comment",
            None,
            60,
            1,
            &mock_http_client,
            &mock_fs,
            &MockPrintTrait::new(),
        )
        .is_ok());
    }
}

#[cfg(test)]
mod tests_fetch_print_keys {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;
    use uzers::mock::MockUsers;
    use uzers::User;

    #[test_log::test]
    fn cannot_switch_user() {
        let root_user = User::new(0, "root", 0);

        let mut user_table = MockUsers::with_current_uid(root_user.uid());
        user_table.add_user(root_user);

        let matches = Args::parse_from(vec!["", "test_user"]);

        assert!(fetch_print_keys(
            matches,
            &user_table,
            &MockSwitchUserTrait::<MockSwitchUserGuardTrait>::new(),
            &MockHttpClientTrait::new(),
            &MockFsTrait::new(),
            &MockPrintTrait::new(),
        )
        .is_err());
    }

    #[test_log::test]
    fn defaults() {
        let expected_user_uid = 1000;
        let expected_user_gid = 1000;
        let expected_user_name = "test_user";
        let expected_user = User::new(expected_user_uid, expected_user_name, expected_user_gid)
            .with_home_dir("/home/test_user");

        let root_user = User::new(0, "root", 0);

        let mut user_table = MockUsers::with_current_uid(expected_user_uid);
        user_table.add_user(expected_user);
        user_table.add_user(root_user);

        let mut mock_fs = MockFsTrait::new();

        let mut mock_metadata_source_defs = MockMetadataTrait::new();
        let source_defs_path = Path::new("/etc/ssh/fetch_keys.conf");
        mock_metadata_source_defs
            .expect_uid_trait()
            .return_const(0u32)
            .times(1);
        mock_metadata_source_defs
            .expect_mode_trait()
            .return_const(0o644u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(source_defs_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata_source_defs)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(source_defs_path))
            .return_once_st(move |_| Ok("1 {1}".to_string()))
            .times(1);

        let mut mock_metadata_cache_directory = MockMetadataTrait::new();
        let expected_cache_path = Path::new("/home/test_user/.ssh/fetch_keys.d/87bb2397-1_2");
        let cache_directory_path = expected_cache_path.parent().unwrap();
        mock_metadata_cache_directory
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata_cache_directory)))
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);

        let mut mock_metadata_user_defs = MockMetadataTrait::new();
        let user_defs_path = Path::new("/home/test_user/.ssh/fetch_keys");
        mock_metadata_user_defs
            .expect_uid_trait()
            .return_const(expected_user_uid)
            .times(1);
        mock_metadata_user_defs
            .expect_mode_trait()
            .return_const(0o644u32)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(user_defs_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata_user_defs)))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(user_defs_path))
            .return_once_st(move |_| Ok("1 2".to_string()))
            .times(1);

        let response_str = "z";
        let mut mock_http_client = MockHttpClientTrait::new();
        mock_http_client
            .expect_request_from_url()
            .with(predicate::eq("2".to_string()), predicate::eq(5))
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);

        mock_fs
            .expect_write()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(response_str),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut mock_print = MockPrintTrait::new();
        mock_print
            .expect_print()
            .with(predicate::eq(response_str))
            .return_const(())
            .times(1);

        let matches = Args::parse_from(vec![""]);

        assert!(fetch_print_keys(
            matches,
            &user_table,
            &MockSwitchUserTrait::<MockSwitchUserGuardTrait>::new(),
            &mock_http_client,
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }

    #[test_log::test]
    fn all_args_specified_including_override_strings() {
        let user_defs = "/tmp/user_defs";
        let source_defs = "/tmp/source_defs";
        let cache_directory = "/tmp/cache_directory";
        let request_timeout = 15;

        let mut mock_switch_user_guard = MockSwitchUserGuardTrait::new();
        mock_switch_user_guard
            .expect_drop_trait()
            .return_const(())
            .times(1);

        let expected_user_uid = 1000;
        let expected_user_gid = 1000;
        let expected_user_name = "test_user";
        let expected_user = User::new(expected_user_uid, expected_user_name, expected_user_gid)
            .with_home_dir("/home/test_user");

        let root_user = User::new(0, "root", 0);

        let mut mock_switch_user = MockSwitchUserTrait::<MockSwitchUserGuardTrait>::new();
        mock_switch_user
            .expect_switch_user_group()
            .withf(move |uid, gid| *uid == expected_user_uid && *gid == expected_user_gid)
            .return_once_st(|_, _| Ok(mock_switch_user_guard))
            .times(1);

        let mut user_table = MockUsers::with_current_uid(root_user.uid());
        user_table.add_user(expected_user);
        user_table.add_user(root_user);

        let mut mock_fs = MockFsTrait::new();

        let mut mock_metadata_cache_directory = MockMetadataTrait::new();
        let expected_cache_path = Path::new("/tmp/cache_directory/87bb2397-1_2");
        let cache_directory_path = expected_cache_path.parent().unwrap();
        mock_metadata_cache_directory
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata_cache_directory)))
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);

        let response_str = "z";
        let mut mock_http_client = MockHttpClientTrait::new();
        mock_http_client
            .expect_request_from_url()
            .with(
                predicate::eq("2".to_string()),
                predicate::eq(request_timeout),
            )
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);

        mock_fs
            .expect_write()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(response_str),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut mock_print = MockPrintTrait::new();
        mock_print
            .expect_print()
            .with(predicate::eq(response_str))
            .return_const(())
            .times(1);

        let matches = Args::parse_from(vec![
            "",
            "test_user",
            response_str,
            "--override-user-def",
            "1 2",
            "--user-defs",
            user_defs,
            "--override-source-def",
            "1 {1}",
            "--source-defs",
            source_defs,
            "--cache-directory",
            cache_directory,
            "--cache-stale",
            "5",
            "--request-timeout",
            &request_timeout.to_string(),
        ]);

        assert!(fetch_print_keys(
            matches,
            &user_table,
            &mock_switch_user,
            &mock_http_client,
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }
    #[test_log::test]
    fn all_args_specified_except_override_string() {
        let user_defs = "/tmp/user_defs";
        let source_defs = "/tmp/source_defs";
        let cache_directory = "/tmp/cache_directory";
        let request_timeout = 15;

        let mut mock_switch_user_guard = MockSwitchUserGuardTrait::new();
        mock_switch_user_guard
            .expect_drop_trait()
            .return_const(())
            .times(1);

        let expected_user_uid = 1000;
        let expected_user_gid = 1000;
        let expected_user_name = "test_user";
        let expected_user = User::new(expected_user_uid, expected_user_name, expected_user_gid)
            .with_home_dir("/home/test_user");

        let root_user = User::new(0, "root", 0);

        let mut mock_switch_user = MockSwitchUserTrait::<MockSwitchUserGuardTrait>::new();
        mock_switch_user
            .expect_switch_user_group()
            .withf(move |uid, gid| *uid == expected_user_uid && *gid == expected_user_gid)
            .return_once_st(|_, _| Ok(mock_switch_user_guard))
            .times(1);

        let mut user_table = MockUsers::with_current_uid(root_user.uid());
        user_table.add_user(expected_user);
        user_table.add_user(root_user);

        let mut mock_fs = MockFsTrait::new();

        let source_defs_path = Path::new(source_defs);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(source_defs_path))
            .return_once_st(|_| Ok(Box::new(MockMetadataTrait::new())))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(source_defs_path))
            .return_once_st(move |_| Ok("1 {1}".to_string()))
            .times(1);

        let mut mock_metadata_cache_directory = MockMetadataTrait::new();
        let expected_cache_path = Path::new("/tmp/cache_directory/87bb2397-1_2");
        let cache_directory_path = expected_cache_path.parent().unwrap();
        mock_metadata_cache_directory
            .expect_is_dir_trait()
            .return_const(true)
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(cache_directory_path))
            .return_once_st(|_| Ok(Box::new(mock_metadata_cache_directory)))
            .times(1);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(expected_cache_path))
            .return_once_st(|_| Err(anyhow!("")))
            .times(1);

        let user_defs_path = Path::new(user_defs);
        mock_fs
            .expect_metadata()
            .with(predicate::eq(user_defs_path))
            .return_once_st(|_| Ok(Box::new(MockMetadataTrait::new())))
            .times(1);
        mock_fs
            .expect_read_to_string()
            .with(predicate::eq(user_defs_path))
            .return_once_st(move |_| Ok("1 2".to_string()))
            .times(1);

        let response_str = "z";
        let mut mock_http_client = MockHttpClientTrait::new();
        mock_http_client
            .expect_request_from_url()
            .with(
                predicate::eq("2".to_string()),
                predicate::eq(request_timeout),
            )
            .return_once_st(move |_, _| Ok(response_str.to_string()))
            .times(1);

        mock_fs
            .expect_write()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(response_str),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);
        mock_fs
            .expect_set_permissions()
            .with(
                predicate::eq(expected_cache_path),
                predicate::eq(fs::Permissions::from_mode(0o644)),
            )
            .return_once_st(move |_, _| Ok(()))
            .times(1);

        let mut mock_print = MockPrintTrait::new();
        mock_print
            .expect_print()
            .with(predicate::eq(response_str))
            .return_const(())
            .times(1);

        let matches = Args::parse_from(vec![
            "",
            "test_user",
            response_str,
            "--user-defs",
            user_defs,
            "--source-defs",
            source_defs,
            "--cache-directory",
            cache_directory,
            "--cache-stale",
            "5",
            "--request-timeout",
            &request_timeout.to_string(),
        ]);

        assert!(fetch_print_keys(
            matches,
            &user_table,
            &mock_switch_user,
            &mock_http_client,
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }
}
