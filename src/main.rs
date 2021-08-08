use anyhow::{ensure, Context, Error, Result};
use crc::{Crc, CRC_32_ISO_HDLC};
use curl::easy::Easy;
use env_logger::Builder;
use lazy_static::lazy_static;
use log::{error, info, warn, LevelFilter};
use regex::{Captures, Regex};
use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::option::Option;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;
use std::str;
use std::time;
use users::os::unix::UserExt;
use users::switch;

// Switches the effective uid to the given user, or self if None
fn switch_user(arg_user_name: Option<&str>) -> Result<users::switch::SwitchUserGuard> {
    let user_name = arg_user_name
        .map(OsString::from)
        .unwrap_or(users::get_effective_username().context("Couldn't get effective username")?);
    let user = users::get_user_by_name(&user_name)
        .context(format!("No user with username {:?}", user_name))?;
    let guard = switch::switch_user_group(user.uid(), user.primary_group_id()).context(format!(
        "Couldn't seteuid to user with username {:?}",
        user_name
    ))?;
    Ok(guard)
}

// If uid_option is Some, ensures the path is owned by, and can be written only by, that user,
// then reads the file at that path
fn ensure_safe_permissions_and_read(path: &Path, uid_option: Option<u32>) -> Result<String> {
    if let Some(uid) = uid_option {
        let sources_defs_path_metadata =
            fs::metadata(path).context(format!("Couldn't stat {:?}", path))?;
        ensure!(
            sources_defs_path_metadata.uid() == uid,
            format!(
                "{:?} not owned by {:?}",
                path,
                users::get_user_by_uid(uid)
                    .context(format!("Couldn't get user with uid {}", uid))?
                    .name()
            )
        );
        ensure!(
            sources_defs_path_metadata.mode() & 0o022 == 0,
            format!("{:?} is writable by group or world", path)
        );
    }
    info!("{:?} has correct permissions. Reading", path);
    fs::read_to_string(path).context(format!("Could not read {:?}", path))
}

// Parses the source definitions file from the given filename, or /etc/ssh/fetch_keys.conf if None,
// into a HashMap of sources to URL templates
fn get_source_defs(override_file_name_option: Option<&str>) -> Result<HashMap<String, String>> {
    let (sources_defs_path, sources_defs_uid_option) = match override_file_name_option {
        Some(override_file_name) => (override_file_name, None),
        None => ("/etc/ssh/fetch_keys.conf", Some(0)),
    };
    info!("Looking for source definitions at {:?}", sources_defs_path);
    let sources_defs_string =
        ensure_safe_permissions_and_read(Path::new(sources_defs_path), sources_defs_uid_option)?;

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

// Returns the path to the home directory of the current effective uid
fn get_current_euid_home_dir() -> Result<PathBuf> {
    let uid = users::get_effective_uid();
    let user =
        users::get_user_by_uid(uid).context(format!("Couldn't get user with uid {}", uid))?;
    Ok(user.home_dir().to_path_buf())
}

// Parses the user's key definitions file from the given filename, or ~/.ssh/fetch_keys if None,
// into a Vec of lines
fn get_user_defs(override_file_name_option: Option<&str>) -> Result<Vec<String>> {
    let (user_defs_pathbuf, user_defs_uid_option) = match override_file_name_option {
        Some(override_file_name) => (PathBuf::from(override_file_name), None),
        None => (
            get_current_euid_home_dir()?.join(".ssh/fetch_keys"),
            Some(users::get_effective_uid()),
        ),
    };
    info!("Looking for user definitions at {:?}", user_defs_pathbuf);
    ensure_safe_permissions_and_read(&user_defs_pathbuf, user_defs_uid_option)
        .map(|s| s.lines().map(|l| l.to_string()).collect::<Vec<String>>())
}

// Obtains the user's key cache directory path from the given filename, or ~/.ssh/fetch_keys.d if None,
// creating it if it doesn't exist
fn get_cache_directory(override_dir_name: Option<&str>) -> Result<PathBuf> {
    let cache_path = override_dir_name
        .map(PathBuf::from)
        .unwrap_or(get_current_euid_home_dir()?.join(".ssh/fetch_keys.d"));
    if cache_path.exists() {
        info!("Found cache directory at {:?}", cache_path);
    } else {
        info!("Creating cache directory at {:?}", cache_path);
        fs::create_dir_all(&cache_path).context(format!(
            "Couldn't create cache directory at {:?}",
            cache_path
        ))?;
    }
    Ok(cache_path)
}

// Returns true if the given key, if Some, is present in the given response string
fn is_key_in_response_str(key_to_find_option: Option<&str>, response_str: String) -> bool {
    match key_to_find_option {
        Some(key_to_find) => response_str.lines().any(|line| line.ends_with(key_to_find)),
        None => false,
    }
}

fn get_cached_response(cache_path: &Path, cache_stale: u64) -> Result<(String, bool)> {
    info!("Looking for a cached response at {:?}", cache_path);

    let cached_result =
        ensure_safe_permissions_and_read(cache_path, Some(users::get_effective_uid()));
    let is_stale = time::SystemTime::now()
        .duration_since(fs::metadata(cache_path)?.modified()?)?
        .as_secs()
        <= cache_stale;

    cached_result.map(|cached_string| (cached_string, is_stale))
}

// Parses a line of the user's key definitions file
// If there exists a cached response and it is fresher than cache_stale seconds, print it, return Ok(Some(cached response)), and omit making the request
// If there exists a cached response but it is staler than cache_stale seconds, dump the cached response into cached_output, and proceed to making the request
// If response code is not 200, then return Ok(None)
// If request is successful, then write the response to the cache and return Ok(Some(response))
// If any other error occurs, return Err()
fn process_user_def_line(
    line: String,
    sources_defs_map: &HashMap<String, String>,
    cache_directory: &Path,
    cached_output: &mut Vec<String>,
    cache_stale: u64,
    request_timeout: u64,
) -> Result<Option<String>> {
    let line_tokens: Vec<String> = line.split_whitespace().map(str::to_string).collect();

    // Skip comment lines and blank lines
    if line_tokens.is_empty() || line_tokens.get(0).unwrap().chars().next().unwrap_or('#') == '#' {
        return Ok(None);
    }

    // Construct the filename in which the cached response lives
    lazy_static! {
        static ref REGEX_URL: Regex = Regex::new(r"\{(?P<index>[[:digit:]]+)\}").unwrap();
        static ref REGEX_FILENAME: Regex = Regex::new(r"[^[:alnum:]_\.\-]+").unwrap();
    }

    let cache_filename = format!(
        "{:x}-{}",
        Crc::<u32>::new(&CRC_32_ISO_HDLC).checksum(line.as_bytes()),
        line_tokens
            .iter()
            .map(|token| REGEX_FILENAME
                .replace_all(&token, |_: &Captures| { "-" })
                .into_owned())
            .collect::<Vec<String>>()
            .join("_")
    );
    let cache_directory_path = cache_directory.join(cache_filename);
    let cache_path = cache_directory_path.to_str().unwrap();

    match get_cached_response(Path::new(cache_path), cache_stale) {
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
            info!("{:?}", e.context("Didn't find a usable cache. Proceeding to make request"));
        }
    }

    // Obtain URL template
    let source = line_tokens.get(0).unwrap();
    let source_def = sources_defs_map.get(source);

    let url =
        source_def.ok_or_else(|| Error::msg(format!("{} is not a defined source", source)))?;

    // Construct request URL
    info!("Found URL template for source {}", source);
    let mut replacement_successful = true;
    let final_url = REGEX_URL.replace_all(url, |caps: &Captures| {
        let index: usize = caps.name("index").unwrap().as_str().parse().unwrap();
        if index < line_tokens.len() {
            &line_tokens.get(index).unwrap()
        } else {
            replacement_successful = false;
            ""
        }
    });
    ensure!(
        replacement_successful,
        format!("Not enough parameters for source {}", source)
    );

    // Make request, timing out after request_timeout seconds
    info!("Making request to {}", final_url);
    let mut response = Vec::new();
    let mut easy = Easy::new();
    easy.url(&final_url)?;
    easy.timeout(time::Duration::from_secs(request_timeout))?;
    easy.follow_location(true)?;
    let transfer_result = {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            response.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()
    };

    if let Err(e) = transfer_result {
        // If request failed, then return Ok(None)
        warn!("Request was unsuccessful: {:?}", e);
        return Ok(None);
    }

    let response_code = easy.response_code()?;
    if response_code != 200 {
        // If response code is not 200, then return Ok(None)
        warn!("Response code was {}, not 200", response_code);
        return Ok(None);
    }

    // If request is successful, then write the response to the cache and return Ok(Some(response))
    info!("Request was successful");

    let response_str = String::from_utf8(response)?;

    print!("{}", response_str);

    info!("Saving response to cache location {:?}", cache_path);
    fs::write(cache_path, &response_str)
        .context(format!("Couldn't write cache at {:?}", cache_path))?;
    fs::set_permissions(cache_path, fs::Permissions::from_mode(0o644))?;
    Ok(Some(response_str))
}

fn fetch_print_keys() -> Result<()> {
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

    // Switch user
    let guard = switch_user(matches.value_of("username"))?;

    // Obtain paths
    let source_defs = get_source_defs(matches.value_of("source-defs"))?;
    let cache_directory = get_cache_directory(matches.value_of("cache-directory"))?;
    let user_defs = get_user_defs(matches.value_of("user-defs"))?;

    let key_to_find = matches.value_of("key");
    let cache_stale = matches.value_of("cache-stale").unwrap_or("60").parse()?;
    let request_timeout = matches.value_of("request-timeout").unwrap_or("5").parse()?;

    let mut cached_output: Vec<String> = Vec::new();

    let mut some_line_output = false;

    // Parse each user definitions line
    for (line_number, line) in user_defs.into_iter().enumerate() {
        let line_result = process_user_def_line(
            line,
            &source_defs,
            &cache_directory,
            &mut cached_output,
            cache_stale,
            request_timeout,
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

    // Switch user back
    drop(guard);

    Ok(())
}

fn main() {
    if let Err(e) = fetch_print_keys() {
        error!("{:?}", e.context("Exiting"));
        process::exit(1);
    };
}
