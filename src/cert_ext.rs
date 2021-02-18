use anyhow::Result;
use yasna::Tag;
use yasna::models::ObjectIdentifier as Oid;

pub fn list_cert_extensions(cert_pem :&str) -> Result<Vec<Oid>> {
	let der = pem::parse(cert_pem)?;
	Ok(list_cert_extensions_der(&der.contents)?)
}

fn push_cert_extensions(tbs_cert_reader :yasna::BERReader, oids :&mut Vec<Oid>) -> yasna::ASN1Result<()> {
	tbs_cert_reader.read_sequence(|rdr| {
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
	Ok(())
}

pub fn list_pre_cert_extensions_der(cert_der :&[u8]) -> Result<Vec<Oid>> {
	let mut oids = Vec::new();
	yasna::parse_der(cert_der, |rdr| {
		push_cert_extensions(rdr, &mut oids)?;
		Ok(())
	})?;
	Ok(oids)
}

pub fn list_cert_extensions_der(cert_der :&[u8]) -> Result<Vec<Oid>> {
	let mut oids = Vec::new();
	yasna::parse_der(cert_der, |rdr| {
		rdr.read_sequence(|rdr| {
			push_cert_extensions(rdr.next(), &mut oids)?;
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
