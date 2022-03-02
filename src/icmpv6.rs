//! Handles parsing of ICMPv6

use crate::icmp::TimeExceeded;
use nom::{number, IResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Unreachable {
    NoRouteToDestination,
    CommunicationAdministrativelyProhibited,
    BeyondScopeOfSourceAddress,
    AddressUnreachable,
    PortUnreachable,
    SourceAddressFailedPolicy,
    RejectRouteToDestination,
    ErrorInSourceRoutingHeader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ParameterProblem {
    ErroneousHeaderField,
    UnrecognizedNextHeader,
    UnrecognizedIPv6Option,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum RouterRenumbering {
    RouterRenumberingCommand,
    RouterRenumberingResult,
    SequenceNumberReset,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NodeInformationQuery {
    DataFieldContainsIPv6,
    DataFieldContainsNameOrEmpty,
    DataFieldContainsIPv4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NodeInformationResponse {
    Successful,
    Refusal,
    UnknownQType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DuplicateAddressRequestCodeSuffix {
    DarMessage,
    EdarMessageWith64BitRovrField,
    EdarMessageWith128BitRovrField,
    EdarMessageWith192BitRovrField,
    EdarMessageWith256BitRovrField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DuplicateAddressConfirmationCodeSuffix {
    DacMessage,
    EdacMessageWith64BitRovrField,
    EdacMessageWith128BitRovrField,
    EdacMessageWith192BitRovrField,
    EdacMessageWith256BitRovrField,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExtendedEchoRequest {
    NoError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum ExtendedEchoReply {
    NoError,
    MalformedQuery,
    NoSuchInterface,
    NoSuchTableEntry,
    MultipleInterfacesStatisfyQuery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Icmpv6Code {
    //Error messages
    DestinationUnreachable(Unreachable),
    PacketTooBig,
    TimeExceeded(TimeExceeded),
    ParameterProblem(ParameterProblem),
    ReservedForError,
 
    //Informational messasges
    EchoRequest,
    EchoReply,
    MulticastListenerQuery,
    MulticastListenerReport,
    MulticastListenerDone,
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation,
    NeighborAdvertisement,
    RedirectMessage,
    RouterRenumbering(RouterRenumbering),
    NodeInformationQuery(NodeInformationQuery),
    NodeInformationResponse(NodeInformationResponse),
    InverseNeighborDiscoverySolicitation,
    InverseNeighborDiscoveryAdvertisement,
    Version2MulticastListenerReport,
    HomeAgentAddressDiscoveryRequestMessage,
    HomeAgentAddressDiscoveryReplyMessage,
    MobilePrefixSolicitation,
    MobilePrefixAdvertisement,
    CertificationPathSolicitation,
    CertificationPathAdvertisement,
    ExperimentalMobilityProtocolMessage,
    MulticastRouterAdvertisement,
    MulticastRouterSolicitation,
    MulticastRouterTermination,
    FMIPv6Messages,
    RPLControlMessage,
    ILNPv6LocatorUpdateMessage,
    DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix),
    DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix),
    MPLControlMessage,
    ExtendedEchoRequest(ExtendedEchoRequest),
    ExtendedEchoReply(ExtendedEchoReply),
    ReservedForInformational,

    PrivateExperimentation(u16),
    Reserved,
    Other(u16),
}

impl From<u16> for Icmpv6Code {
    fn from(raw: u16) -> Self {
        let [t, c] = raw.to_be_bytes();
        match t {
            0x01 => match c {
                0x00 => Self::DestinationUnreachable(Unreachable::NoRouteToDestination),
                0x01 => Self::DestinationUnreachable(Unreachable::CommunicationAdministrativelyProhibited),
                0x02 => Self::DestinationUnreachable(Unreachable::BeyondScopeOfSourceAddress),
                0x03 => Self::DestinationUnreachable(Unreachable::AddressUnreachable),
                0x04 => Self::DestinationUnreachable(Unreachable::PortUnreachable),
                0x05 => Self::DestinationUnreachable(Unreachable::SourceAddressFailedPolicy),
                0x06 => Self::DestinationUnreachable(Unreachable::RejectRouteToDestination),
                0x07 => Self::DestinationUnreachable(Unreachable::ErrorInSourceRoutingHeader),
                _ => Self::Other(raw),
            },
            0x02 => Self::PacketTooBig,
            0x03 => match c {
                0x00 => Self::TimeExceeded(TimeExceeded::TTL),
                0x01 => Self::TimeExceeded(TimeExceeded::FragmentReassembly),
                _ => Self::Other(raw),
            },
            0x04 => match c {
                0x00 => Self::ParameterProblem(ParameterProblem::ErroneousHeaderField),
                0x01 => Self::ParameterProblem(ParameterProblem::UnrecognizedNextHeader),
                0x02 => Self::ParameterProblem(ParameterProblem::UnrecognizedIPv6Option),
                _ => Self::Other(raw),
            },
            0x64 => Self::PrivateExperimentation(raw),
            0x65 => Self::PrivateExperimentation(raw),
            0x7F => Self::ReservedForError,
            0x80 => Self::EchoRequest,
            0x81 => Self::EchoReply,
            0x82 => Self::MulticastListenerQuery,
            0x83 => Self::MulticastListenerReport,
            0x84 => Self::MulticastListenerDone,
            0x85 => Self::RouterSolicitation,
            0x86 => Self::RouterAdvertisement,
            0x87 => Self::NeighborSolicitation,
            0x88 => Self::NeighborAdvertisement,
            0x89 => Self::RedirectMessage,
            0x8A => match c {
                0x00 => Self::RouterRenumbering(RouterRenumbering::RouterRenumberingCommand),
                0x01 => Self::RouterRenumbering(RouterRenumbering::RouterRenumberingResult),
                0xFF => Self::RouterRenumbering(RouterRenumbering::SequenceNumberReset),
                _ => Self::Other(raw),
            },
            0x8B => match c {
                0x00 => Self::NodeInformationQuery(NodeInformationQuery::DataFieldContainsIPv6),
                0x01 => Self::NodeInformationQuery(NodeInformationQuery::DataFieldContainsNameOrEmpty),
                0x02 => Self::NodeInformationQuery(NodeInformationQuery::DataFieldContainsIPv4),
                _ => Self::Other(raw),
            },
            0x8C => match c {
                0x00 => Self::NodeInformationResponse(NodeInformationResponse::Successful),
                0x01 => Self::NodeInformationResponse(NodeInformationResponse::Refusal),
                0x02 => Self::NodeInformationResponse(NodeInformationResponse::UnknownQType),
                _ => Self::Other(raw),
            },
            0x8D => Self::InverseNeighborDiscoverySolicitation,
            0x8E => Self::InverseNeighborDiscoveryAdvertisement,
            0x8F => Self::Version2MulticastListenerReport,
            0x90 => Self::HomeAgentAddressDiscoveryRequestMessage,
            0x91 => Self::HomeAgentAddressDiscoveryReplyMessage,
            0x92 => Self::MobilePrefixSolicitation,
            0x93 => Self::MobilePrefixAdvertisement,
            0x94 => Self::CertificationPathSolicitation,
            0x95 => Self::CertificationPathAdvertisement,
            0x96 => Self::ExperimentalMobilityProtocolMessage,
            0x97 => Self::MulticastRouterAdvertisement,
            0x98 => Self::MulticastRouterSolicitation,
            0x99 => Self::MulticastRouterTermination,
            0x9A => Self::FMIPv6Messages,
            0x9B => Self::RPLControlMessage,
            0x9C => Self::ILNPv6LocatorUpdateMessage,
            0x9D => match c {
                0x00 => Self::DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix::DarMessage),
                0x01 => Self::DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix::EdarMessageWith64BitRovrField),
                0x02 => Self::DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix::EdarMessageWith128BitRovrField),
                0x03 => Self::DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix::EdarMessageWith192BitRovrField),
                0x04 => Self::DuplicateAddressRequestCodeSuffix(DuplicateAddressRequestCodeSuffix::EdarMessageWith256BitRovrField),
                _ => Self::Other(raw),
            },
            0x9E => match c {
                0x00 => Self::DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix::DacMessage),
                0x01 => Self::DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix::EdacMessageWith64BitRovrField),
                0x02 => Self::DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix::EdacMessageWith128BitRovrField),
                0x03 => Self::DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix::EdacMessageWith192BitRovrField),
                0x04 => Self::DuplicateAddressConfirmationCodeSuffix(DuplicateAddressConfirmationCodeSuffix::EdacMessageWith256BitRovrField),
                _ => Self::Other(raw),
            },
            0x9F => Self::MPLControlMessage,
            0xA0 => match c {
                0x00 => Self::ExtendedEchoRequest(ExtendedEchoRequest::NoError),
                _ => Self::Other(raw),
            },
            0xA1 => match c {
                0x00 => Self::ExtendedEchoReply(ExtendedEchoReply::NoError),
                0x01 => Self::ExtendedEchoReply(ExtendedEchoReply::MalformedQuery),
                0x02 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchInterface),
                0x03 => Self::ExtendedEchoReply(ExtendedEchoReply::NoSuchTableEntry),
                0x04 => Self::ExtendedEchoReply(ExtendedEchoReply::MultipleInterfacesStatisfyQuery),
                _ => Self::Other(raw),
            },
            0xC8 => Self::PrivateExperimentation(raw),
            0xC9 => Self::PrivateExperimentation(raw),
            0xFF => Self::ReservedForInformational,
            _ => Self::Other(raw),
        }
    }
}

fn parse_icmpv6_code(input: &[u8]) -> IResult<&[u8], Icmpv6Code> {
    let (input, code) = number::streaming::be_u16(input)?;

    Ok((input, code.into()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Icmpv6Data {
    None,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Icmpv6Header {
    pub code: Icmpv6Code,
    pub checksum: u16,
    pub data: Icmpv6Data,
}

pub fn parse_icmpv6_header(input: &[u8]) -> IResult<&[u8], Icmpv6Header> {
    let (input, code) = parse_icmpv6_code(input)?;
    let (input, checksum) = number::streaming::be_u16(input)?;

    let (input, data) = match code {
        _ => (input, Icmpv6Data::None),
    };

    Ok((
        input,
        Icmpv6Header {
            code,
            checksum,
            data,
        },
    ))
}
