use anyhow::{ensure, Context, Error, Result};
use clap::{App, Arg, ArgMatches};
use crc::{Crc, CRC_32_ISO_HDLC};
use curl::easy::Easy;
use env_logger::Builder;
use lazy_static::lazy_static;
use log::{error, info, warn, LevelFilter};
use mockall::automock;
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
use users::os::unix::UserExt;
use users::switch;
use users::{User, Users, UsersCache};

#[automock]
trait SwitchUserGuardTrait {
    fn drop_trait(&self);
}

impl SwitchUserGuardTrait for switch::SwitchUserGuard {
    fn drop_trait(&self) {
        drop(self);
    }
}

#[automock]
trait SwitchUserTrait {
    fn switch_user_group(
        &self,
        uid: users::uid_t,
        gid: users::gid_t,
    ) -> Result<Box<dyn SwitchUserGuardTrait>, io::Error>;
}

struct SwitchUser;

impl SwitchUserTrait for SwitchUser {
    fn switch_user_group(
        &self,
        uid: users::uid_t,
        gid: users::gid_t,
    ) -> Result<Box<dyn SwitchUserGuardTrait>, io::Error> {
        switch::switch_user_group(uid, gid)
            .map(|switch_user_guard| Box::new(switch_user_guard) as Box<dyn SwitchUserGuardTrait>)
    }
}

// Switches the effective uid to the given user
fn switch_user<T, U>(
    user_name_option: Option<&str>,
    user_table: &mut T,
    switch_user_trait: &U,
) -> Result<(User, Option<Box<dyn SwitchUserGuardTrait>>)>
where
    T: Users,
    U: SwitchUserTrait,
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

#[automock]
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

#[automock]
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
    }
    info!("{:?} has correct permissions. Reading", path);
    fs_trait
        .read_to_string(path)
        .context(format!("Could not read {:?}", path))
        .map(|read_string| (read_string, metadata))
}

// Parses the source definitions &str into a HashMap of sources to URL templates
fn get_source_defs(source_defs_string: &str) -> Result<HashMap<String, String>> {
    let mut source_defs_map = HashMap::new();
    for line in source_defs_string.lines() {
        let line_tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if line_tokens.len() < 2 || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#'
        {
            continue;
        }
        source_defs_map.insert(
            line_tokens.get(0).unwrap().to_string(),
            line_tokens.get(1).unwrap().to_string(),
        );
    }

    ensure!(
        !source_defs_map.is_empty(),
        "Read sources definitions file, but no sources were defined in it"
    );

    Ok(source_defs_map)
}

// Parses the user's key definitions &str into a Vec of lines
fn get_user_defs(user_defs_string: &str) -> Vec<String> {
    user_defs_string
        .lines()
        .map(str::to_string)
        .collect::<Vec<String>>()
}

// Construct the filename in which the cached response lives
fn get_cache_filename(line_tokens: &[String], cache_directory: &Path) -> PathBuf {
    // Canonicalise user definition line by combining whitespace
    let line_join_ascii_whitespace = line_tokens.join(" ");
    let crc_line =
        Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(line_join_ascii_whitespace.as_bytes());

    lazy_static! {
        static ref REGEX_FILENAME: Regex = Regex::new(r"[^[:alnum:]_\.\-]+").unwrap();
    }

    // Replace all characters that aren't alphanumeric, _, ., or - with -
    let line_join_hyphen = line_tokens
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

// Construct URL, given HashMap of sources to URL templates as well as tokens
fn construct_url(
    source_defs_map: &HashMap<String, String>,
    line_tokens: Vec<String>,
) -> Result<String> {
    let source = line_tokens.get(0).unwrap();
    let source_def = source_defs_map.get(source);

    let url_template =
        source_def.ok_or_else(|| Error::msg(format!("{} is not a defined source", source)))?;

    lazy_static! {
        static ref REGEX_URL: Regex = Regex::new(r"\{(?P<index>[[:digit:]]+)\}").unwrap();
    }

    info!("Found URL template for source {}", source);
    let mut replacement_successful = true;
    let url = REGEX_URL
        .replace_all(url_template, |caps: &Captures| {
            let index: usize = caps.name("index").unwrap().as_str().parse().unwrap();
            if index < line_tokens.len() {
                &line_tokens.get(index).unwrap()
            } else {
                replacement_successful = false;
                ""
            }
        })
        .to_string();
    ensure!(
        replacement_successful,
        format!("Not enough parameters for source {}", source)
    );
    Ok(url)
}

#[automock]
trait HttpClientTrait {
    fn request_from_url(&self, url: String, request_timeout: u64) -> Result<String>;
}

struct CurlHttpClient;

impl HttpClientTrait for CurlHttpClient {
    // Make request, timing out after request_timeout seconds
    fn request_from_url(&self, url: String, request_timeout: u64) -> Result<String> {
        info!("Making request to {}", url);
        let mut response = Vec::new();
        let mut easy = Easy::new();
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

// Parses a line of the user's key definitions file
// If there exists a cached response and it is fresher than cache_stale seconds, print it, return Ok(Some(cached response)), and omit making the request
// If there exists a cached response but it is staler than cache_stale seconds, dump the cached response into cached_output, and proceed to making the request
// If response code is not 200, then return Ok(None)
// If request is successful, then write the response to the cache and return Ok(Some(response))
// If any other error occurs, return Err()
fn process_user_def_line<T, U>(
    user: &User,
    line: String,
    source_defs_map: &HashMap<String, String>,
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
    let line_tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();

    // Skip comment lines and blank lines
    if line_tokens.is_empty() || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#' {
        return Ok(None);
    }

    let cache_path = get_cache_filename(&line_tokens, cache_directory);

    info!("Looking for a cached response at {:?}", cache_path);
    match ensure_safe_permissions_and_read(&cache_path, Some(user), fs_trait).and_then(
        |(cached_string, metadata)| {
            is_cache_fresh(metadata, cache_stale)
                .map(|is_cache_fresh_bool| (is_cache_fresh_bool, cached_string))
        },
    ) {
        Ok((true, cached_string)) => {
            info!("Found fresh cached response. Omitting request");
            return Ok(Some(cached_string));
        }
        Ok((false, cached_string)) => {
            info!("Cache is stale. Proceeding to make request");
            cached_output.push(cached_string);
        }
        Err(e) => {
            info!(
                "{:?}",
                e.context("Didn't find a usable cache. Proceeding to make request")
            );
        }
    }

    let url =
        construct_url(source_defs_map, line_tokens).context("Couldn't construct request URL")?;

    let response_str = http_client_trait
        .request_from_url(url, request_timeout)
        .context("Request was unsuccessful")?;

    if let Err(e) = write_to_cache(cache_path, &response_str, fs_trait) {
        warn!("{:?}", e.context("Couldn't write to cache"));
    }

    Ok(Some(response_str))
}

// Returns true if the given key, if Some, is present in the given response string
fn is_key_in_response_str(key_to_find_option: Option<&str>, response_str: String) -> bool {
    match key_to_find_option {
        Some(key_to_find) => response_str.lines().any(|line| line.ends_with(key_to_find)),
        None => false,
    }
}

#[automock]
trait PrintTrait {
    fn print(&self, s: &str);
}

struct StdOut;

impl PrintTrait for StdOut {
    fn print(&self, s: &str) {
        print!("{}", s);
    }
}

// Parse and process a Vec of user definitions lines
fn process_user_defs<T, U, V>(
    user: &User,
    source_defs: HashMap<String, String>,
    cache_directory: &Path,
    user_defs: Vec<String>,
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

    for (line_number, line) in user_defs.into_iter().enumerate() {
        let line_result = process_user_def_line(
            user,
            line,
            &source_defs,
            cache_directory,
            &mut cached_output,
            cache_stale,
            request_timeout,
            http_client_trait,
            fs_trait,
        );

        match line_result {
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

fn fetch_print_keys<T, U, V, W>(
    matches: ArgMatches,
    switch_user_trait: &T,
    http_client_trait: &U,
    fs_trait: &V,
    print_trait: &W,
) -> Result<()>
where
    T: SwitchUserTrait,
    U: HttpClientTrait,
    V: FsTrait,
    W: PrintTrait,
{
    let mut users_table = UsersCache::new();
    let (user, guard) = switch_user(
        matches.value_of("username"),
        &mut users_table,
        switch_user_trait,
    )?;

    process_user_defs(
        &user,
        {
            let (source_defs_path, user_option) = match matches.value_of("source-defs") {
                Some(override_path) => (Path::new(override_path), None),
                None => (
                    Path::new("/etc/ssh/fetch_keys.conf"),
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
                    source_defs_path,
                    user_option.as_ref(),
                    fs_trait,
                )?
                .0,
            )
        }?,
        &match matches.value_of("cache-directory") {
            Some(override_path) => PathBuf::from(override_path),
            None => user.home_dir().join(".ssh/fetch_keys.d"),
        },
        {
            let (user_defs_path, user_option) = match matches.value_of("user-defs") {
                Some(override_path) => (PathBuf::from(override_path), None),
                None => (user.home_dir().join(".ssh/fetch_keys"), Some(&user)),
            };
            info!("Looking for user definitions at {:?}", user_defs_path);
            get_user_defs(
                &ensure_safe_permissions_and_read(&user_defs_path, user_option, fs_trait)?.0,
            )
        },
        matches.value_of("key"),
        matches.value_of("cache-stale").unwrap_or("60").parse()?,
        matches.value_of("request-timeout").unwrap_or("5").parse()?,
        http_client_trait,
        fs_trait,
        print_trait,
    )?;

    // Switch user back
    if let Some(b) = guard {
        (*b).drop_trait();
    }

    Ok(())
}

// Read command-line arguments
fn get_args_app() -> App<'static, 'static> {
    App::new("ssh_fetch_keys")
        .version("0.1.0")
        .author("Scott C Wang")
        .arg(
            Arg::with_name("username")
                .help("Username for which to fetch keys")
                .index(1),
        )
        .arg(
            Arg::with_name("key")
                .help("Key to look for (will stop once found)")
                .index(2),
        )
        .arg(
            Arg::with_name("user-defs")
                .help("Override user definitions file")
                .long("user-defs")
                .short("u")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("source-defs")
                .help("Override source definitions file")
                .long("source-defs")
                .short("s")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache-directory")
                .help("Override cache directory")
                .long("cache-directory")
                .short("c")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cache-stale")
                .help("Skip making a new request to a source if it has been less than this many seconds since that source's cache was last modified. 0 to ignore any caches. Default 60")
                .long("cache-stale")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("request-timeout")
                .help("Timeout for requests in seconds. Default 5")
                .long("request-timeout")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("verbosity")
                .help("Verbosity. Can be given multiple times")
                .long("verbose")
                .short("v")
                .multiple(true)
        )
}

fn main() {
    let matches = get_args_app().get_matches();

    // Set log level
    let mut builder = Builder::from_default_env();
    builder.filter_level(match matches.occurrences_of("verbosity") {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    });
    builder.init();

    if let Err(e) = fetch_print_keys(
        matches,
        &SwitchUser {},
        &CurlHttpClient {},
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
    use users::mock::MockUsers;

    fn prepare_switch_user_test(
        user_name_option: Option<&str>,
        expect_switch_user_call: bool,
    ) -> Result<(User, Option<Box<dyn SwitchUserGuardTrait>>)> {
        let mut mock_switch_user: MockSwitchUserTrait = MockSwitchUserTrait::new();
        let expected_switch_user_guard: Box<dyn SwitchUserGuardTrait> =
            Box::new(MockSwitchUserGuardTrait::new()) as Box<dyn SwitchUserGuardTrait>;

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

    #[test]
    fn test_some_user_name() {
        let (actual_user, expected_switch_user_guard_option) =
            prepare_switch_user_test(Some("test_user"), true).unwrap();

        assert_eq!(actual_user.name(), "test_user");
        assert_eq!(actual_user.uid(), 1000);
        assert_eq!(actual_user.primary_group_id(), 1000);

        assert!(expected_switch_user_guard_option.is_some());
    }

    #[test]
    fn test_none_user_name() {
        let (actual_user, expected_switch_user_guard_option) =
            prepare_switch_user_test(None, false).unwrap();

        assert_eq!(actual_user.name(), "current_user");
        assert_eq!(actual_user.uid(), 1001);
        assert_eq!(actual_user.primary_group_id(), 1001);

        assert!(expected_switch_user_guard_option.is_none());
    }

    #[test]
    fn test_bogus_user_name() {
        assert!(prepare_switch_user_test(Some("bogus_user"), false).is_err());
    }
}

#[cfg(test)]
mod tests_ensure_safe_permissions_and_read {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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
        expected_result_vec_pairs: Option<Vec<(&str, &str)>>,
    ) {
        let actual_source_defs_map_result = get_source_defs(source_defs_string);

        match actual_source_defs_map_result {
            Ok(actual_source_defs_map) => {
                assert_eq!(
                    actual_source_defs_map,
                    expected_result_vec_pairs
                        .unwrap()
                        .into_iter()
                        .map(|(a, b)| (a.to_string(), b.to_string()))
                        .collect()
                );
            }
            Err(_) => {
                assert!(expected_result_vec_pairs.is_none());
            }
        }
    }

    #[test]
    fn test_empty() {
        prepare_get_source_defs_test("", None);
    }

    #[test]
    fn test_one_line_two_tokens() {
        prepare_get_source_defs_test("1 2", Some(vec![("1", "2")]));
    }

    #[test]
    fn test_extra_spaces() {
        prepare_get_source_defs_test("1   2", Some(vec![("1", "2")]));
    }

    #[test]
    fn test_comment_line() {
        prepare_get_source_defs_test("1 2\n # comment", Some(vec![("1", "2")]));
    }

    #[test]
    fn test_blank_line() {
        prepare_get_source_defs_test("1 2\n\n3 4", Some(vec![("1", "2"), ("3", "4")]));
    }

    #[test]
    fn test_two_lines() {
        prepare_get_source_defs_test("1 2\n3 4", Some(vec![("1", "2"), ("3", "4")]));
    }

    #[test]
    fn test_three_tokens() {
        prepare_get_source_defs_test("1 2 3", Some(vec![("1", "2")]));
    }

    #[test]
    fn test_one_token() {
        prepare_get_source_defs_test("1 2\n3", Some(vec![("1", "2")]));
    }
}

#[cfg(test)]
mod tests_get_user_defs {
    use super::*;

    fn prepare_get_user_defs_test(user_defs_string: &str, expected_result_vec: Vec<&str>) {
        assert_eq!(
            get_user_defs(user_defs_string),
            expected_result_vec
                .into_iter()
                .map(str::to_string)
                .collect::<Vec<String>>()
        );
    }

    #[test]
    fn test_empty() {
        prepare_get_user_defs_test("", vec![]);
    }

    #[test]
    fn test_one_line() {
        prepare_get_user_defs_test("1 2", vec!["1 2"]);
    }

    #[test]
    fn test_two_lines() {
        prepare_get_user_defs_test("1\n2", vec!["1", "2"]);
    }
}

#[cfg(test)]
mod tests_get_cache_filename {
    use super::*;

    fn prepare_get_cache_filename_test(
        line: Vec<&str>,
        cache_directory: &str,
        expected_result: &str,
    ) {
        assert_eq!(
            get_cache_filename(
                &line
                    .into_iter()
                    .map(str::to_string)
                    .collect::<Vec<String>>(),
                Path::new(cache_directory)
            ),
            PathBuf::from(expected_result)
        );
    }

    #[test]
    fn test_one_token() {
        prepare_get_cache_filename_test(vec!["1"], "/tmp", "/tmp/83dcefb7-1");
    }

    #[test]
    fn test_two_tokens() {
        prepare_get_cache_filename_test(vec!["1", "2"], "/tmp", "/tmp/87bb2397-1_2");
    }

    #[test]
    fn test_allowed_nonalphanumeric_character() {
        prepare_get_cache_filename_test(vec!["1-2"], "/tmp", "/tmp/32155dda-1-2");
    }

    #[test]
    fn test_forbidden_nonalphanumeric_character() {
        prepare_get_cache_filename_test(vec!["1*2"], "/tmp", "/tmp/7d54cb1d-1-2");
    }

    #[test]
    fn test_directory() {
        prepare_get_cache_filename_test(vec!["1*2"], "/tmp/test", "/tmp/test/7d54cb1d-1-2");
    }
}

#[cfg(test)]
mod tests_is_cache_fresh {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn test_err() {
        let mut mock_metadata = MockMetadataTrait::new();
        mock_metadata
            .expect_modified_trait()
            .return_once_st(|| Err(anyhow!("")))
            .times(1);
        assert!(is_cache_fresh(Box::new(mock_metadata), 0).is_err());
    }

    #[test]
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

    #[test]
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
        source_defs_map_pairs: Vec<(&str, &str)>,
        line_tokens_str: &str,
        expected_result_url: Result<&str>,
    ) {
        let source_defs_map: HashMap<String, String> = source_defs_map_pairs
            .into_iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let line_tokens = line_tokens_str
            .split_whitespace()
            .map(str::to_string)
            .collect();

        let actual_construct_url_result = construct_url(&source_defs_map, line_tokens);

        match actual_construct_url_result {
            Ok(actual_construct_url) => {
                assert_eq!(actual_construct_url, expected_result_url.unwrap());
            }
            Err(_) => {
                assert!(expected_result_url.is_err());
            }
        }
    }

    #[test]
    fn test_undefined_source() {
        prepare_construct_url_test(vec![], "a b", Err(anyhow!("")));
    }

    #[test]
    fn test_correct_parameters() {
        prepare_construct_url_test(vec![("a", "z{1}{2}")], "a b c", Ok("zbc"));
    }

    #[test]
    fn test_too_few_parameters() {
        prepare_construct_url_test(vec![("a", "z{1}{2}")], "a b", Err(anyhow!("")));
    }

    #[test]
    fn test_too_many_parameters() {
        prepare_construct_url_test(vec![("a", "z{1}{2}{3}")], "a b", Err(anyhow!("")));
    }
}

#[cfg(test)]
mod tests_write_to_cache {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test]
    fn test_bad_cache_path_parent() {
        assert!(write_to_cache(PathBuf::from("/"), "", &MockFsTrait::new()).is_err());
    }

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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

    #[test]
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
mod tests_process_user_def_line {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test]
    fn test_comment_line() {
        assert!(matches!(
            process_user_def_line(
                &User::new(0, "", 0),
                "# comment".to_string(),
                &HashMap::new(),
                Path::new(""),
                &mut vec![],
                0,
                0,
                &MockHttpClientTrait::new(),
                &MockFsTrait::new()
            ),
            Ok(None)
        ));
    }

    #[test]
    fn test_blank_line() {
        assert!(matches!(
            process_user_def_line(
                &User::new(0, "", 0),
                " ".to_string(),
                &HashMap::new(),
                Path::new(""),
                &mut vec![],
                0,
                0,
                &MockHttpClientTrait::new(),
                &MockFsTrait::new()
            ),
            Ok(None)
        ));
    }

    #[test]
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
            "1 2".to_string(),
            &HashMap::new(),
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

    #[test]
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
            "1 2".to_string(),
            &vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
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

    #[test]
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
            "1 2".to_string(),
            &vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
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

    #[test]
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

        assert!(process_user_def_line(
            &User::new(1000u32, "", 0),
            "1 2".to_string(),
            &HashMap::new(),
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

    #[test]
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
            "1 2".to_string(),
            &vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
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

    #[test]
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
            "1 2".to_string(),
            &vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
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

    #[test]
    fn none() {
        assert!(!is_key_in_response_str(None, "".to_string()));
    }

    #[test]
    fn some_no() {
        assert!(!is_key_in_response_str(Some("a"), "b\nc".to_string()));
    }

    #[test]
    fn some_yes() {
        assert!(is_key_in_response_str(Some("a"), "b\na".to_string()));
    }
}

#[cfg(test)]
mod tests_process_user_defs {
    use super::*;
    use anyhow::anyhow;
    use mockall::predicate;

    #[test]
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

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            cache_directory,
            vec!["1 2".to_string(), "3 4".to_string()],
            Some(response_str),
            60,
            0,
            &MockHttpClientTrait::new(),
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }

    #[test]
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

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            cache_directory,
            vec!["1 2".to_string(), "# comment".to_string()],
            None,
            1,
            1,
            &mock_http_client,
            &mock_fs,
            &mock_print,
        )
        .is_ok());
    }

    #[test]
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

        assert!(process_user_defs(
            &User::new(1000u32, "", 0),
            vec![("1", "{1}")]
                .into_iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            cache_directory,
            vec!["1 2".to_string(), "# comment".to_string()],
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
