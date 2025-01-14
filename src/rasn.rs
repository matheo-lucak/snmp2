use crate::{asn1, AsnReader, Varbinds};

pub trait IntoRasnIterator<'a> {
    fn into_rasn_iter(self) -> RasnInterator<'a>;
}

impl<'a> IntoRasnIterator<'a> for Varbinds<'a> {
    fn into_rasn_iter(self) -> RasnInterator<'a> {
        RasnInterator { inner: self.inner }
    }
}

pub struct RasnInterator<'a> {
    inner: AsnReader<'a>,
}

impl<'a> Iterator for RasnInterator<'a> {
    type Item = rasn_snmp::v2::VarBind;

    fn next(&mut self) -> Option<Self::Item> {
        // Translation of snmpv2 VarBind to rasn Varbind is tricky as we don't have easily access to the snmpv2 asn reader buffer.
        //
        // We first read a sequence which gives a buffer of the *Varbind Payload*, pointing to A (see diagram below)
        // The Varbind Name repr is easy to parse, as rasn::ber will take only the first required bytes to parse the object.
        //
        // Then we are left with a buffer pointing A that needs to point to B.
        // With a temporary reader we simulate the parsing of the Varbind Name repr to get the leftover buffer, pointing to B.
        //
        // Memory representation of Varbind :
        // | Varbind Header | Varbind Payload                                         |
        // |----------------|---------------------------------------------------------|
        // | IDENT | LENGTH | PAYLOAD                                                 |
        // |----------------|---------------------------------------------------------|
        // |                | Varbind Name repr            | Varbind Value repr       |
        // |----------------|---------------------------------------------------------|
        // |                | IDENT | LENGTH | PAYLOAD     | IDENT | LENGTH | PAYLOAD |
        //                  ^                              ^
        //                  A                              B

        let seq = self.inner.read_raw(asn1::TYPE_SEQUENCE).ok()?;

        let object_name: rasn_snmp::v2::ObjectName = rasn::ber::decode(seq).ok()?;

        let mut tmp_reader = AsnReader::from_bytes(seq);
        let _ = tmp_reader.read_byte().ok()?;
        let payload_len = tmp_reader.read_length().ok()?;
        let header_len = 1 + if payload_len < 128 { 1 } else { 2 };

        let (_, seq) = seq.split_at(header_len + payload_len);

        let object_value: rasn_snmp::v2::VarBindValue = rasn::ber::decode(seq).ok()?;

        Some(rasn_snmp::v2::VarBind {
            name: object_name,
            value: object_value,
        })
    }
}

pub trait TryAsOid<'a> {
    type Error;

    fn try_as_oid(&self) -> Result<asn1_rs::Oid<'a>, Self::Error>;
}

impl<'a> TryAsOid<'a> for rasn::types::ObjectIdentifier {
    type Error = asn1_rs::OidParseError;

    fn try_as_oid(&self) -> Result<asn1_rs::Oid<'a>, Self::Error> {
        let slice: &[u32] = self;
        let owned = slice.iter().map(|x| *x as u64).collect::<Vec<_>>();
        asn1_rs::Oid::from(&owned)
    }
}

impl<'a> TryAsOid<'a> for rasn::types::Oid {
    type Error = asn1_rs::OidParseError;

    fn try_as_oid(&self) -> Result<asn1_rs::Oid<'a>, Self::Error> {
        let slice: &[u32] = self;
        let owned = slice.iter().map(|x| *x as u64).collect::<Vec<_>>();
        asn1_rs::Oid::from(&owned)
    }
}
