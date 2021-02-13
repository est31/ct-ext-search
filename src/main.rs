use anyhow::Result;
use yasna::Tag;
use yasna::models::ObjectIdentifier as Oid;
use clap::Clap;
use ctclient::CTClient;

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
struct LstrOpts {}

static USER_AGENT :&str = concat!("ct-ext-search ", env!("CARGO_PKG_VERSION"),
	". https://github.com/est31/ct-ext-search");

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
			let public_key = base64::decode("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAETeBmZOrzZKo4xYktx9gI2chEce3cw/tbr5xkoQlmhB18aKfsxD+MnILgGNl0FOm0eYGilFVi85wLRIOhK8lxKw==").unwrap();
			const URL: &str = "https://ct.googleapis.com/logs/argon2021/";
			// TODO convertability of the error, TODO user agent, TODO library neutral means of access
			let mut client = CTClient::new_from_latest_th(URL, &public_key).unwrap();
			loop {
				let update_result = client.update(Some(|certs: &[openssl::x509::X509]| {
					for c in certs {
						let der = c.to_der().unwrap();
						let oids = list_cert_extensions_der(&der).unwrap();
						println!("{:?}", oids);
					}
				}));
				if update_result.is_err() {
					eprintln!("Error: {}", update_result.unwrap_err());
					break;
				}
			}
		},
    }
	Ok(())
}
