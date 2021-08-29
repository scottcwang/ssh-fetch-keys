use anyhow::{ensure, Context, Error, Result};
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
trait SwitchUserGuardTrait {}

impl SwitchUserGuardTrait for switch::SwitchUserGuard {}

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

// Parses the source definitions file from the given path into a HashMap of sources to URL templates;
// if a user is given, checks the path is owned by and writeable only by that user
fn get_source_defs<U>(
    sources_defs_path: &Path,
    sources_defs_user_option: Option<&User>,
    fs_trait: &U,
) -> Result<HashMap<String, String>>
where
    U: FsTrait,
{
    info!("Looking for source definitions at {:?}", sources_defs_path);
    let (sources_defs_string, _) =
        ensure_safe_permissions_and_read(sources_defs_path, sources_defs_user_option, fs_trait)?;

    let mut sources_defs_map = HashMap::new();
    for line in sources_defs_string.lines() {
        let line_tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();
        if line_tokens.len() < 2 || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#'
        {
            continue;
        }
        sources_defs_map.insert(
            line_tokens.get(0).unwrap().to_string(),
            line_tokens.get(1).unwrap().to_string(),
        );
    }

    ensure!(
        !sources_defs_map.is_empty(),
        "Read sources definitions file, but no sources were defined in it"
    );

    Ok(sources_defs_map)
}

// Parses the user's key definitions file from the given path into a Vec of lines;
// if a user is given, checks the path is owned by and writeable only by that user
fn get_user_defs<U>(
    user_defs_path: &Path,
    user_option: Option<&User>,
    fs_trait: &U,
) -> Result<Vec<String>>
where
    U: FsTrait,
{
    info!("Looking for user definitions at {:?}", user_defs_path);
    ensure_safe_permissions_and_read(user_defs_path, user_option, fs_trait)
        .map(|(s, _)| s.lines().map(|l| l.to_string()).collect::<Vec<String>>())
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

fn get_cached_response<U>(
    user: &User,
    cache_path: &Path,
    cache_stale: u64,
    fs_trait: &U,
) -> Result<(String, bool)>
where
    U: FsTrait,
{
    info!("Looking for a cached response at {:?}", cache_path);

    let (cached_result, metadata) =
        ensure_safe_permissions_and_read(cache_path, Some(user), fs_trait)?;
    let is_stale = time::SystemTime::now()
        .duration_since(metadata.modified_trait()?)?
        .as_secs()
        <= cache_stale;

    Ok((cached_result, is_stale))
}

// Construct URL, given HashMap of sources to URL templates as well as tokens
fn construct_url(
    sources_defs_map: &HashMap<String, String>,
    line_tokens: Vec<String>,
) -> Result<String> {
    let source = line_tokens.get(0).unwrap();
    let source_def = sources_defs_map.get(source);

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

// Make request, timing out after request_timeout seconds
fn request_from_url(url: String, request_timeout: u64) -> Result<String> {
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

fn write_to_cache<U>(cache_path: PathBuf, response_str: &str, fs_trait: &U) -> Result<()>
where
    U: FsTrait,
{
    let cache_path_parent = cache_path
        .parent()
        .ok_or_else(|| Error::msg(format!("Couldn't get path parent of {:?}", cache_path)))?;
    if cache_path_parent.exists() {
        ensure!(
            cache_path_parent.is_dir(),
            format!("{:?} exists but is not a directory", cache_path_parent)
        );
        info!("Found cache directory at {:?}", cache_path_parent);
    } else {
        info!("Creating cache directory at {:?}", cache_path_parent);
        fs_trait.create_dir_all(cache_path_parent).context(format!(
            "Couldn't create cache directory at {:?}",
            cache_path_parent
        ))?;
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
fn process_user_def_line<U>(
    user: &User,
    line: String,
    sources_defs_map: &HashMap<String, String>,
    cache_directory: &Path,
    cached_output: &mut Vec<String>,
    cache_stale: u64,
    request_timeout: u64,
    fs_trait: &U,
) -> Result<Option<String>>
where
    U: FsTrait,
{
    let line_tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();

    // Skip comment lines and blank lines
    if line_tokens.is_empty() || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#' {
        return Ok(None);
    }

    let cache_path = get_cache_filename(&line_tokens, cache_directory);

    match get_cached_response(user, &cache_path, cache_stale, fs_trait) {
        Ok((cached_string, true)) => {
            info!("Found fresh cached response. Omitting request");
            print!("{}", &cached_string);
            return Ok(Some(cached_string));
        }
        Ok((cached_string, false)) => {
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
        construct_url(sources_defs_map, line_tokens).context("Couldn't construct request URL")?;

    let response_str =
        request_from_url(url, request_timeout).context("Request was unsuccessful")?;

    print!("{}", response_str);

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

// Parse and process a Vec of user definitions lines
fn process_user_defs<U>(
    user: &User,
    source_defs: HashMap<String, String>,
    cache_directory: &Path,
    user_defs: Vec<String>,
    key_to_find: Option<&str>,
    cache_stale: u64,
    request_timeout: u64,
    fs_trait: &U,
) -> Result<()>
where
    U: FsTrait,
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
            fs_trait,
        );

        match line_result {
            Ok(Some(line_retrieved_response)) => {
                // If there was no error processing this line, and there exists a fresh cache or the response code is 200 for this line ...
                some_line_output = true;
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
        warn!("None of the source definitions provided a recent cached response or a successful request. Using stale caches");

        for cached_output_entry in cached_output {
            print!("{}", cached_output_entry);
        }
    }

    Ok(())
}

fn fetch_print_keys<T, U>(switch_user_trait: &T, fs_trait: &U) -> Result<()>
where
    T: SwitchUserTrait,
    U: FsTrait,
{
    // Read command-line arguments
    let matches = clap::App::new("ssh_fetch_keys")
        .version("0.1.0")
        .author("Scott C Wang")
        .arg(
            clap::Arg::with_name("username")
                .help("Username for which to fetch keys")
                .index(1),
        )
        .arg(
            clap::Arg::with_name("key")
                .help("Key to look for (will stop once found)")
                .index(2),
        )
        .arg(
            clap::Arg::with_name("user-defs")
                .help("Override user definitions file")
                .long("user-defs")
                .short("u")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("source-defs")
                .help("Override source definitions file")
                .long("source-defs")
                .short("s")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("cache-directory")
                .help("Override cache directory")
                .long("cache-directory")
                .short("c")
                .takes_value(true),
        )
        .arg(
            clap::Arg::with_name("cache-stale")
                .help("Skip making a new request to a source if it has been less than this many seconds since that source's cache was last modified. 0 to ignore any caches. Default 60")
                .long("cache-stale")
                .takes_value(true)
        )
        .arg(
            clap::Arg::with_name("request-timeout")
                .help("Timeout for requests in seconds. Default 5")
                .long("request-timeout")
                .takes_value(true)
        )
        .arg(
            clap::Arg::with_name("verbosity")
                .help("Verbosity. Can be given multiple times")
                .long("verbose")
                .short("v")
                .multiple(true)
        )
        .get_matches();

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

    let mut users_table = UsersCache::new();
    let (user, guard) = switch_user(
        matches.value_of("username"),
        &mut users_table,
        switch_user_trait,
    )?;

    process_user_defs(
        &user,
        match matches.value_of("source-defs") {
            Some(override_path) => get_source_defs(Path::new(override_path), None, fs_trait),
            None => get_source_defs(
                Path::new("/etc/ssh/fetch_keys.conf"),
                Some(
                    users_table
                        .get_user_by_uid(0)
                        .context("Couldn't get root user")?
                        .as_ref(),
                ),
                fs_trait,
            ),
        }?,
        &match matches.value_of("cache-directory") {
            Some(override_path) => PathBuf::from(override_path),
            None => user.home_dir().join(".ssh/fetch_keys.d"),
        },
        match matches.value_of("user-defs") {
            Some(override_path) => get_user_defs(Path::new(override_path), None, fs_trait),
            None => get_user_defs(
                &user.home_dir().join(".ssh/fetch_keys"),
                Some(&user),
                fs_trait,
            ),
        }?,
        matches.value_of("key"),
        matches.value_of("cache-stale").unwrap_or("60").parse()?,
        matches.value_of("request-timeout").unwrap_or("5").parse()?,
        fs_trait,
    )?;

    // Switch user back
    drop(guard);

    Ok(())
}

fn main() {
    if let Err(e) = fetch_print_keys(&SwitchUser {}, &StdFs {}) {
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
