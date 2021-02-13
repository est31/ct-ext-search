use anyhow::Result;
use yasna::Tag;
use yasna::models::ObjectIdentifier as Oid;

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

const RCGEN_TEST_CERT :&str = "
-----BEGIN CERTIFICATE-----
MIIBdjCCARygAwIBAgIBKjAKBggqhkjOPQQDAjAwMRgwFgYDVQQKDA9DcmFiIHdp
ZGdpdHMgU0UxFDASBgNVBAMMC01hc3RlciBDZXJ0MCAXDTc1MDEwMTAwMDAwMFoY
DzQwOTYwMTAxMDAwMDAwWjAwMRgwFgYDVQQKDA9DcmFiIHdpZGdpdHMgU0UxFDAS
BgNVBAMMC01hc3RlciBDZXJ0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEyhYW
U6ums18N9XglqoQPnw04zdQrVYgH6p051oQ7Bjh5H6/zaOrv1iUrAzo1lNkmK371
2h9zzgnwnvbAQCuXLqMlMCMwIQYDVR0RBBowGIILY3JhYnMuY3JhYnOCCWxvY2Fs
aG9zdDAKBggqhkjOPQQDAgNIADBFAiEAivRIEKj6uyNwv/K9tBXtV38dCgLJyWLh
7PCCUwwhsZ8CIH1sVLzmqQs5yvZXAARSMfCeDqAaeCWv9AztAnY5gE+M
-----END CERTIFICATE-----
";

	#[test]
	fn check_rcgen_exts() -> Result<()> {
		let oids = list_cert_extensions(RCGEN_TEST_CERT)?;
		assert_eq!(oids, &[Oid::from_slice(&[2, 5, 29, 17])]);
		Ok(())
	}
}


fn main() -> Result<()> {
	/*let oids = list_cert_extensions()?;
	println!("{:?}", oids);*/
	Ok(())
}
