use anyhow::{Result, bail};
use yasna::Tag;
use yasna::models::ObjectIdentifier as Oid;
use clap::Clap;
use ctclient::CTClient;
use serde::Deserialize;
use std::convert::TryInto;

fn list_cert_extensions(cert_pem :&str) -> Result<Vec<Oid>> {
	let der = pem::parse(cert_pem)?;
	Ok(list_cert_extensions_der(&der.contents)?)
}

fn list_cert_extensions_der(cert_der :&[u8]) -> Result<Vec<Oid>> {
	let mut oids = Vec::new();
	yasna::parse_der(cert_der, |rdr| {
		rdr.read_sequence(|rdr| {
			rdr.next().read_sequence(|rdr| {
				// version
				rdr.next().read_der()?;
				// serial number
				rdr.next().read_der()?;
				// signature
				rdr.next().read_der()?;
				// issuer
				rdr.next().read_der()?;
				// validity
				rdr.next().read_der()?;
				// subject
				rdr.next().read_der()?;
				// subjectPublicKeyInfo
				rdr.next().read_der()?;
				// TODO issuerUniqueID / subjectUniqueID
				// extensions
				rdr.read_optional(|rdr| {
					// Extensions has tag number [3]
					if rdr.lookahead_tag()?.tag_number == 3 {
						rdr.read_tagged(Tag::context(3), |rdr| {
							rdr.read_sequence(|rdr| {
								// Iterate over the extensions
								while let Some(_) = rdr.read_optional(|rdr| {
									let ext = rdr.read_der()?;
									yasna::parse_der(&ext, |rdr| {
										rdr.read_sequence(|rdr| {
											oids.push(rdr.next().read_oid()?);
											let r = rdr.next();
											if r.lookahead_tag()? == yasna::tags::TAG_BOOLEAN {
												// critical
												r.read_der()?;
												// extnValue
												rdr.next().read_bytes()?;
											} else {
												// extnValue
												r.read_bytes()?;
											}
											Ok(())
										})
									})?;
									Ok(())
								})? {}
								Ok(())
							})
						})?;
					}
					Ok(())
				})?;
				Ok(())
			})?;
			// signatureAlgorithm
			rdr.next().read_der()?;
			// signature
			rdr.next().read_der()?;
			Ok(())
		})
	})?;
	Ok(oids)
}

#[cfg(test)]
mod tests {
	use super::*;

const RCGEN_TEST_CERT :&str = include_str!("rcgen-example.pem");

	#[test]
	fn check_rcgen_exts() -> Result<()> {
		let oids = list_cert_extensions(RCGEN_TEST_CERT)?;
		assert_eq!(oids, &[Oid::from_slice(&[2, 5, 29, 17])]);
		Ok(())
	}
}

#[derive(Deserialize)]
struct OperatorList {
	pub operators :Vec<Operator>,
}

#[derive(Deserialize)]
struct Operator {
	pub name :String,
	pub logs :Vec<Log>,
}

#[derive(Deserialize)]
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

fn main() -> Result<()> {
	let opts :Opts = Opts::parse();
	match opts.op {
		SubCommand::ListExt(opts) => {
			let pem = std::fs::read_to_string(&opts.pem_file)?;
			let oids = list_cert_extensions(&pem)?;
			println!("{:?}", oids);
		},
		SubCommand::Dl(opts) => {
			println!("Downloading from log at {}", opts.url);
			let client = reqwest::blocking::Client::builder()
				.user_agent(USER_AGENT)
				.build()?;
			let res = client.get(&format!("{}/ct/v1/get-sth", opts.url)).send()?;
			println!("{}", res.text()?);
		},
		SubCommand::LiveStream(opts) => {
			let operators = obtain_all_operator_list()?;
			let log = operators.operators.iter().map(|op| op.logs.iter())
				.flatten()
				.find(|log| log.url == opts.url);
			let log = if let Some(log) = log {
				log
			} else {
				bail!("Couldn't find the log in the known log list. Unable to obtain the public key.");
			};
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
						let oids = list_cert_extensions_der(&der).unwrap();
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
			let client = reqwest::blocking::Client::builder()
				.user_agent(USER_AGENT)
				.build()?;
			let mut start = opts.start;
			const STEP_SIZE :u64 = 30;
			let mut smallest_size = (opts.end - opts.start + 1).min(STEP_SIZE);
			while start < opts.end {
				let end = start + smallest_size - 1;

				print!("Requesting {} entries: {}..={}. ", end - start + 1, start, end);
				let res = client.get(&format!("{}/ct/v1/get-entries?start={}&end={}", opts.url, start, end)).send()?;
				let entries_res = res.json::<EntriesResult>()?;
				let entries_len = entries_res.entries.len().try_into().unwrap();
				// We use saturating_sub here because the result might return more than we asked for
				let entries_left = (opts.end - start).saturating_sub(entries_len);
				println!(" => Got {} entries in result. {} to go.", entries_len, entries_left);
				if entries_len == 0 {
					bail!("Last request to obtain entries returned none!\
						Aborting to prevent infinite number of requests to the API.");
				}
				start += entries_len;
				smallest_size = STEP_SIZE.min(entries_len);

				// TODO do something with the entries_res
			}
		},
    }
	Ok(())
}
