use anyhow::{Result, bail};
use clap::Clap;
use ctclient::CTClient;
use serde::Deserialize;
use std::{convert::TryInto, io::Write};
use std::io::Read;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Sha256, Digest};

use rocksdb::{DB, Options};

mod cert_ext;

#[derive(Deserialize)]
struct OperatorList {
	pub operators :Vec<Operator>,
}

#[derive(Deserialize)]
struct Operator {
	pub name :String,
	pub logs :Vec<Log>,
}

#[derive(Deserialize, Clone)]
struct Log {
	pub description :String,
	pub key :String,
	pub url :String,
}

fn obtain_all_operator_list() -> Result<OperatorList> {
	obtain_operator_list_from_url("https://www.gstatic.com/ct/log_list/v2/all_logs_list.json")
}

fn obtain_trusted_operator_list() -> Result<OperatorList> {
	obtain_operator_list_from_url("https://www.gstatic.com/ct/log_list/v2/log_list.json")
}

fn obtain_operator_list_from_url(url :&str) -> Result<OperatorList> {
	let client = reqwest::blocking::Client::builder()
		.user_agent(USER_AGENT)
		.build()?;
	let res = client.get(url).send()?;
	let list = res.json::<OperatorList>()?;
	Ok(list)
}

#[derive(Deserialize)]
struct EntriesResult {
	pub entries :Vec<CtEntry>,
}

#[derive(Deserialize)]
struct CtEntry {
	pub leaf_input :String,
	pub extra_data :String,
}

#[derive(Clap)]
struct Opts {
	#[clap(subcommand)]
	op :SubCommand,
}

#[derive(Clap)]
enum SubCommand {
	ListExt(ListExtOpts),
	Dl(DlOpts),
	Filter(FilterOpts),
	LiveStream(LstrOpts),
	Scan(ScanOpts),
}

#[derive(Clap)]
struct ListExtOpts {
	//#[clap(short, long)]
	pem_file :String,
}

#[derive(Clap)]
struct DlOpts {
	url :String,
	start :u64,
	end :u64,
}

#[derive(Clap)]
struct FilterOpts {
	url :String,
	start :u64,
	end :u64,
}

#[derive(Clap)]
struct LstrOpts {
	url :String,
}

#[derive(Clap)]
struct ScanOpts {
	url :String,
	start :u64,
	end :u64,
}

fn dl_range(url :&str, op_start :u64, op_end :u64, mut f :impl FnMut(u64, EntriesResult) -> Result<()>) -> Result<()> {
	let client = reqwest::blocking::Client::builder()
		.user_agent(USER_AGENT)
		.build()?;
	let mut start = op_start;
	const STEP_SIZE :u64 = 30;
	let mut smallest_size = (op_end - op_start + 1).min(STEP_SIZE);
	while start < op_end {
		let end = op_end.min(start + smallest_size - 1);

		print!("Requesting {} entries: {}..={}.", end - start + 1, start, end);
		let res = client.get(&format!("{}/ct/v1/get-entries?start={}&end={}", url, start, end)).send()?;
		let entries_res = res.json::<EntriesResult>()?;
		let entries_len = entries_res.entries.len().try_into().unwrap();
		// We use saturating_sub here because the result might return more than we asked for
		let entries_left = (op_end - start).saturating_sub(entries_len);
		println!(" => Got {} entries in result. {} to go.", entries_len, entries_left);
		f(start, entries_res)?;
		if entries_len == 0 {
			bail!("Last request to obtain entries returned none!\
				Aborting to prevent infinite number of requests to the API.");
		}
		start += entries_len;
		smallest_size = STEP_SIZE.min(entries_len);
	}
	Ok(())
}

fn get_matching_log(url :&str) -> Result<Log> {
	let operators = obtain_all_operator_list()?;
	let log = operators.operators.iter().map(|op| op.logs.iter())
		.flatten()
		.find(|log| log.url == url);
	let log = if let Some(log) = log {
		log
	} else {
		bail!("Couldn't find the log in the known log list. Unable to obtain the public key.");
	};
	Ok(log.clone())
}

static USER_AGENT :&str = concat!("ct-ext-search ", env!("CARGO_PKG_VERSION"),
	". https://github.com/est31/ct-ext-search");

// id-ce-extKeyUsage in
// https://tools.ietf.org/html/rfc5280#section-4.2.1.12
#[allow(unused)]
const OID_EXT_KEY_USAGE :&[u64] = &[2, 5, 29, 37];

// id-ce-nameConstraints in
/// https://tools.ietf.org/html/rfc5280#section-4.2.1.10
const OID_NAME_CONSTRAINTS :&[u64] = &[2, 5, 29, 30];

static INTERESTING_OIDS :&[&[u64]] = &[
	//OID_EXT_KEY_USAGE,
	OID_NAME_CONSTRAINTS,
];

struct TimestampedEntry {
	timestamp :u64,
	signed_entry :Entry,
	// TODO extensions
}
enum Entry {
	X509Entry(Vec<u8>),
	PrecertEntry([u8; 32], Vec<u8>),
}

fn read_u24(rdr :&mut impl Read) -> Result<u32> {
	Ok(((rdr.read_u8()? as u32) << 16) + ((rdr.read_u8()? as u32) << 8) + rdr.read_u8()? as u32)
}

fn parse_timestamped_entry(buf :&[u8]) -> Result<TimestampedEntry> {
	let mut leaf_input_buf_rdr = buf;
	let version = leaf_input_buf_rdr.read_u8()?;
	if version != 0 {
		bail!("Invalid version of MerkleTreeLeaf: {}", version);
	}
	let leaf_type = leaf_input_buf_rdr.read_u8()?;
	if leaf_type != 0 {
		bail!("Invalid type of MerkleTreeLeaf: {}", leaf_type);
	}
	let timestamp = leaf_input_buf_rdr.read_u64::<BigEndian>()?;
	let entry_type = leaf_input_buf_rdr.read_u16::<BigEndian>()?;

	let entry = match entry_type {
		0 /* x509_entry */ => {
			let leaf_certificate_len = read_u24(&mut leaf_input_buf_rdr)?;
			//println!("Leaf cert len: {}", leaf_certificate_len);
			let mut der = vec![0; leaf_certificate_len as usize];
			leaf_input_buf_rdr.read_exact(&mut der)?;
			Entry::X509Entry(der)
		},
		1 /* precert_entry */ => {
			let mut issuer_key_hash = [0u8; 32];
			leaf_input_buf_rdr.read_exact(&mut issuer_key_hash)?;
			let precert_tbs_len = read_u24(&mut leaf_input_buf_rdr)?;
			//println!("Precert tbs len: {}", precert_tbs_len);
			let mut der = vec![0; precert_tbs_len as usize];
			leaf_input_buf_rdr.read_exact(&mut der)?;
			Entry::PrecertEntry(issuer_key_hash, der)
		},
		t => {
			bail!("Invalid entry type {}", t);
		},
	};
	Ok(TimestampedEntry {
		timestamp,
		signed_entry : entry,
	})
}

fn read_certificate_chain(mut rdr :impl Read) -> Result<Vec<Vec<u8>>> {
	let chain_len = read_u24(&mut rdr)?;
	let mut res = Vec::with_capacity(chain_len as usize);
	for _ in 0..chain_len {
		let cert_len = read_u24(&mut rdr)?;
		let mut cert_buf = vec![0; cert_len as usize];
		rdr.read_exact(&mut cert_buf)?;
		res.push(cert_buf);
	}
	Ok(res)
}
fn read_precert_chain_entry(buf :&[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
	let mut rdr = buf;
	let cert_len = read_u24(&mut rdr)?;
	let mut pre_cert_buf = vec![0; cert_len as usize];
	rdr.read_exact(&mut pre_cert_buf)?;
	let precertificate_chain = read_certificate_chain(&mut rdr)?;
	Ok((pre_cert_buf, precertificate_chain))
}

/// LogEntryType in CT 1.0, VersionedTransType in CT 2.0
#[derive(Debug, PartialEq, Eq)]
enum LogEntryType {
	X509Entry,
	PrecertEntry,
	Other(u16),
}

struct LogEntry {
	entry_type :LogEntryType,
	leaf :Vec<u8>,
	chain :Vec<Vec<u8>>,
}

fn read_log_entry(buf :&[u8]) -> Result<LogEntry> {
	let mut rdr = buf;
	let entry_type = rdr.read_u16::<BigEndian>()?;
	let entry_type = match entry_type {
		0 /* x509_entry */ => LogEntryType::X509Entry,
		1 /* precert_entry */ => LogEntryType::PrecertEntry,
		// CT 1.0 only supports two log entry types.
		// CT 2.0 adds a few additional ones. We don't
		// have full support for CT 2.0, but not bailing
		// lets us read what we understand at least.
		v => LogEntryType::Other(v),
	};
	let cert_len = read_u24(&mut rdr)?;
	println!("cel {}", cert_len);
	let mut pre_cert_buf = vec![0; cert_len as usize];
	rdr.read_exact(&mut pre_cert_buf)?;
	let precertificate_chain = read_certificate_chain(&mut rdr)?;

	Ok(LogEntry {
		entry_type,
		leaf : pre_cert_buf,
		chain : precertificate_chain,
	})
}

fn main() -> Result<()> {
	let opts :Opts = Opts::parse();
	match opts.op {
		SubCommand::ListExt(opts) => {
			let pem = std::fs::read_to_string(&opts.pem_file)?;
			let oids = cert_ext::list_cert_extensions(&pem)?;
			println!("{:?}", oids);
		},
		SubCommand::Dl(opts) => {
			println!("Downloading from log at {}", opts.url);
			let log = get_matching_log(&opts.url)?;
			println!("Found log '{}' matching URL", log.description);
			let public_key = base64::decode(&log.key).unwrap();
			let mut hasher = Sha256::new();
			hasher.update(public_key);
			let pubkey_hash = hasher.finalize();
			let db_path = format!("db/{}.db", hex::encode(pubkey_hash));
			let mut db_opts = Options::default();
			db_opts.create_if_missing(true);
			let db = DB::open(&db_opts, db_path)?;
			dl_range(&opts.url,opts.start, opts.end, |start , entry_result| {
				for (id, entry) in entry_result.entries.iter().enumerate() {
					let id = start + id as u64;
					let mut db_value = Vec::new();
					let leaf_input_raw = base64::decode(&entry.leaf_input)?;
					let extra_data_raw = base64::decode(&entry.extra_data)?;
					db_value.write_u64::<BigEndian>(leaf_input_raw.len() as u64).unwrap();
					db_value.write_all(&leaf_input_raw).unwrap();
					db_value.write_u64::<BigEndian>(extra_data_raw.len() as u64).unwrap();
					db_value.write_all(&extra_data_raw).unwrap();
					let mut key = Vec::with_capacity(9);
					key.push(1);
					key.extend_from_slice(&id.to_be_bytes());
					db.put(&key, &db_value)?;
				}
				Ok(())
			})?;

			/*let client = reqwest::blocking::Client::builder()
				.user_agent(USER_AGENT)
				.build()?;
			let res = client.get(&format!("{}/ct/v1/get-sth", opts.url)).send()?;
			println!("{}", res.text()?);*/
		},
		SubCommand::Filter(opts) => {
			println!("Filtering log with url {}", opts.url);
			let log = get_matching_log(&opts.url)?;
			println!("Found log '{}' matching URL", log.description);
			let public_key = base64::decode(&log.key).unwrap();
			let mut hasher = Sha256::new();
			hasher.update(public_key);
			let pubkey_hash = hasher.finalize();
			let db_path = format!("db/{}.db", hex::encode(pubkey_hash));
			let db = DB::open_default(db_path)?;
			for id in opts.start ..= opts.end {
				let mut key = Vec::with_capacity(9);
				key.push(1);
				key.extend_from_slice(&id.to_be_bytes());
				let db_value = db.get(&key)?;
				let db_value = if let Some(v) = db_value {
					v
				} else {
					// Maybe error here? IDK.
					println!("Can't find entry for id {} in db. Maybe download first?", id);
					break;
				};
				let mut val_rdr = db_value.as_slice();
				let leaf_input_raw_len = val_rdr.read_u64::<BigEndian>()?;
				let mut leaf_input_raw = vec![0; leaf_input_raw_len as usize];
				val_rdr.read_exact(&mut leaf_input_raw)?;
				let extra_data_raw_len = val_rdr.read_u64::<BigEndian>()?;
				let mut extra_data_raw = vec![0; extra_data_raw_len as usize];
				val_rdr.read_exact(&mut extra_data_raw)?;

				let entry = parse_timestamped_entry(&leaf_input_raw)?;
				let (oids, der) = match &entry.signed_entry {
					Entry::X509Entry(der) => {
						(cert_ext::list_cert_extensions_der(der)?, der)
					},
					Entry::PrecertEntry(_issuer_key_hash, der) => {
						(cert_ext::list_pre_cert_extensions_der(der)?, der)
					},
				};
				let log_entry = read_log_entry(&extra_data_raw)?;
				for oid in oids {
					for ioid in INTERESTING_OIDS {
						if ioid == oid.components() {
							let chain :String = log_entry.chain.iter()
								.enumerate()
								.map(|(i, c)| format!("\n  --> Chain entry {}: {} ", i, base64::encode(&c))).collect();
							println!("Match found. Base64: {}. {}", base64::encode(&der), chain);
						}
					}
				}
			}
		},
		SubCommand::LiveStream(opts) => {
			let log = get_matching_log(&opts.url)?;
			println!("Found log '{}' matching URL", log.description);
			let mut ctr = 0u64;
			let public_key = base64::decode(&log.key).unwrap();
			// TODO convertability of the error, TODO user agent, TODO library neutral means of access (no X509 type)
			let mut client = CTClient::new_from_latest_th(&log.url, &public_key).unwrap();
			loop {
				let update_result = client.update(Some(|certs: &[openssl::x509::X509]| {
					let mut match_found = false;
					for c in certs {
						ctr += 1;
						if ctr % 1_000 == 0 {
							println!("Reached {} many certs", ctr);
						}
						let der = c.to_der().unwrap();
						let oids = cert_ext::list_cert_extensions_der(&der).unwrap();
						for oid in oids {
							for ioid in INTERESTING_OIDS {
								if ioid == oid.components() {
									match_found = true;
								}
							}
						}
					}
					if match_found {
						println!("Match found. Chain:");
						for c in certs {
							println!("{}", String::from_utf8(c.to_pem().unwrap()).unwrap());
						}
					}
				}));
				if update_result.is_err() {
					eprintln!("Error: {}", update_result.unwrap_err());
					break;
				}
			}
		},
		SubCommand::Scan(opts) => {
			if opts.start > opts.end {
				bail!("Start is not before end: {} > {}", opts.start, opts.end);
			}
			println!("Downloading from log at {}", opts.url);

			dl_range(&opts.url, opts.start,opts.end, |_start, entries_res| {
				for entry in entries_res.entries {
					let leaf_input_buf = base64::decode(&entry.leaf_input)?;
					let entry = parse_timestamped_entry(&leaf_input_buf)?;
					let (oids, der) = match &entry.signed_entry {
						Entry::X509Entry(der) => {
							(cert_ext::list_cert_extensions_der(der)?, der)
						},
						Entry::PrecertEntry(_issuer_key_hash, der) => {
							(cert_ext::list_pre_cert_extensions_der(der)?, der)
						},
					};
					for oid in oids {
						for ioid in INTERESTING_OIDS {
							if ioid == oid.components() {
								println!("Match found. Base64: {}", base64::encode(&der));
							}
						}
					}
				}
				Ok(())
			})?;
		},
    }
	Ok(())
}
