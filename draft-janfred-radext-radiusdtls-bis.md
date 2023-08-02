---
title: "(Datagram) Transport Layer Security ((D)TLS Encryption for RADIUS"
abbrev: "RADIUS over (D)TLS"
category: std

obsoletes: 6614 7360

docname: draft-janfred-radext-radiusdtls-bis-latest
submissiontype: IETF
v: 3
area: "Security"
workgroup: "RADIUS EXTensions"
keyword:
 - RADIUS
 - TLS
venue:
  group: "RADIUS EXTensions"
  type: "Working Group"
  mail: "radext@ietf.org"

author:
  - name: Jan-Frederik Rieckers
    org: Deutsches Forschungsnetz | German National Research and Education Network
    street: Alexanderplatz 1
    code: 10178
    city: Berlin
    country: Germany
    email: rieckers@dfn.de
    abbrev: DFN
    uri: www.dfn.de
  - name: Stefan Winter
    org: Fondation Restena | Restena Foundation
    street: 2, avenue de l'Université
    code: 4365
    city: Esch-sur-Alzette
    country: Luxembourg
    email: stefan.winter@restena.lu
    abbrev: RESTENA
    uri: www.restena.lu

normative:

informative:


--- abstract

This document specifies a transport profile for RADIUS using Transport Layer Security (TLS) over TCP or Datagram Transport Layer Security (DTLS) over UDP as the transport protocol.
This enables encrypting the RADIUS traffic as well as dynamic trust relationships between RADIUS servers.

--- middle

{:jf: source="Janfred"}

# Introduction

The RADIUS protocol as described in {{!RFC2865}}, {{!RFC2866}}, {{!RFC5176}} and others is a widely deployed authentication, authorization and accounting solution.
However, the deployment experience has shown several shortcomings, as its dependency on the unreliable transport protocol UDP and the lack of confidentiality for large parts of its packet payload.
Additionally the confidentiality and integrity mechanisms rely on the MD5 algorithm, which has been proven to be insecure.
Although RADIUS/(D)TLS does not remove the MD5-based mechanisms, it adds confidentiality and integrity protection through the TLS layer.
For an updated version of RADIUS/(D)TLS without need for MD5 see {{?I-D.ietf-radext-radiusv11}}

## Purpose of RADIUS/(D)TLS

The main focus of RADIUS/TLS and RADIUS/DTLS is to provide means to secure communication between RADIUS peers using TLS or DTLS.
The most important use of this specification lies in roaming environments where RADIUS packets need to be transferred through different administrative domains and untrusted, potentially hostile networks.
An example for a worldwide roaming environment that uses RADIUS over TLS to secure communication is eduroam as described in {{?RFC7593}}

## Changes from RFC6614 (RADIUS/TLS) and RFC7360 (RADIUS/DTLS)

* {{?RFC6614}} referenced {{?RFC6613}} for TCP-related specification, RFC6613 on the other hand had some specification for RADIUS/TLS.
  These specifications have been merged into this document.
* RFC6614 marked TLSv1.1 or later as mandatory, this specification requires TLSv1.2 as minimum and recommends usage of TLSv1.3
* RFC6614 allowed usage of TLS compression, this document forbids it.
* RFC6614 lists support for TLS-PSK as optional, this document changes this to recommended.
* The mandatory-to-implement cipher suites are changing to more up-to-date cipher suites.
* The specification regarding steps for certificate verification has been updated

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Within this document we will use the following terms:

RADIUS/(D)TLS node:
: a RADIUS-over-(D)TLS client or server

RADIUS/(D)TLS client:
: a RADIUS-over-(D)TLS instance that initiates a new connection

RADIUS/(D)TLS server:
: a RADIUS-over-(D)TLS instance that listens on a RADIUS-over-(D)TLS port and accepts new connections

RADIUS/UDP:
: a classic RADIUS transport over UDP as defined in {{RFC2865}}

Whenever "(D)TLS" or "RADIUS/(D)TLS" is mentioned, the specification applies for both RADIUS/TLS and RADIUS/DTLS.
Where "TLS" or "RADIUS/TLS" is mentioned, the specification only applies to RADIUS/TLS, where "DTLS" or "RADIUS/DTLS" is mentioned it only applies to RADIUS/DTLS.

Implementations SHOULD support both RADIUS/TLS and RADIUS/DTLS, but to be compliant to this specification they can choose to implement only one of the two. [^choose-your-weapon]{:jf}

[^choose-your-weapon]: I'm not exactly sure if this text is good. My thought was also to add a text like "You have to say RADIUS/TLS according to RFC????, if you want to say 'compliant with RFC????' you need to implement both". But maybe this is the pessimist in me that fears that companies will advocate "we support RFC????", but only use one or the other and we end up with incompatible systems, because A does RADIUS/TLS and B does RADIUS/DTLS.

# Changes to RADIUS

This section discusses the needed changes to the RADIUS packet format ({{pktformat}}), port usage and shared secrets ({{portusage}}) and RADIUS MIBs ({{radius_mib}}).

## Packet format
{: #pktformat}

[^src_6613_2_1]

[^src_6613_2_1]: Source: RFC6613, Section 2.1 with minimal changes: Removed paragraph about required ability to store shared secrets. Also added last paragraphs from RFC 7360, Section 2.1

The RADIUS packet format is unchanged from {{RFC2865}}, {{RFC2866}} and {{RFC5176}}.
Specifically, all of the following portions of RADIUS MUST be unchanged when using RADIUS/(D)TLS:

* Packet format
* Permitted codes
* Request Authenticator calculation
* Response Authenticator calculation
* Minimum packet length
* Maximum packet length
* Attribute format
* Vendor-Specific Attribute (VSA) format
* Permitted data types
* Calculation of dynamic attributes such as CHAP-Challenge, or Message-Authenticator
* Calculation of "encrypted" attributes such as Tunnel-Password.

The use of (D)TLS transport does not change the calculation of security-related fields (such as the Response-Authenticator) in RADIUS {{RFC2865}} or RADIUS Dynamic Authorization {{RFC5176}}.
Calculation of attributes such as User-Password {{RFC2865}} or Message-Authenticator {{!RFC3579}} also does not change.

The changes to RADIUS implementations required to implement this specification are largely limited to the portions that send and receive packets on the network and the establishment of the (D)TLS connection.

The requirement that RADIUS remain largely unchanged ensures the simplest possible implementation and widest interoperability of the specification.

We note that for RADIUS/DTLS the DTLS encapsulation of RADIUS means that RADIUS packets have an additional overhead due to DTLS.
This is discussed further in {{dtls_spec}}

## Default ports and shared secrets
{: #portusage}

IANA has reserved ports for RADIUS/TLS and RADIUS/DTLS.
Since authentication of peers, confidentiality, and integrity protection is achieved on the (D)TLS layer, the shared secret for the RADIUS packets is set to a static string, depending on the method.
The calculation of security-related fields such as Response-Authenticator, Message-Authenticator or encrypted attributes MUST be performed using this shared secret.

|Protocol | Port | Shared Secret |
|---------|-----|-----|
| RADIUS/TLS | 2083/tcp | "radsec" |
| RADIUS/DTLS | 2083/udp | "radius/dtls" |

The default ports for RADIUS/UDP (1812/udp, 1813/udp) and RADIUS/TCP (1812/tcp, 1813/tcp) SHOULD NOT be used for RADIUS/(D)TLS.

RADIUS/(D)TLS does not use separate ports for authentication, accounting and dynamic authorization changes.
The source port is arbitrary.
[^considerations]{:jf}

RADIUS/TLS servers MUST immediately start the TLS negotiation when a new connection is opened.
They MUST close the connection and discard any data sent if the connecting client does not start a TLS negotiation.

RADIUS/DTLS servers MUST silently discard any packet they receive that is not a new DTLS negotiation or a packet sent over a DTLS session established earlier.

RADIUS/(D)TLS peers MUST NOT use the old RADIUS/UDP or RADIUS/TCP ports for RADIUS/DTLS or RADIUS/TLS.

[^considerations]: TODO: add reference to considerations regarding the multi-purpose use of one port.

## RADIUS MIBs
{: #radius_mib}

[^mib]{:jf}

[^mib]: Is this actually still needed? RFC6613, Section 2.3 says "will need to be updated in the future". Is this the time?

## Detecting Live Servers

[^src_6613_2_4]

[^src_6613_2_4]: Source: RFC6613, Section 2.4 with minor modifications, Last paragraph: RFC6613 Section 2.6.5.

As RADIUS is a "hop-by-hop" protocol, a RADIUS proxy shields the client from any information about downstream servers.
While the client may be able to deduce the operational state of the local server (i.e., proxy), it cannot make any determination about the operational state of the downstream servers.

Within RADIUS, proxies typically only forward traffic between the NAS and RADIUS servers, and they do not generate their own response.
As a result, when a NAS does not receive a response to a request, this could be the result of packet loss between the NAS and proxy, a problem on the proxy, loss between the RADIUS proxy and server, or a problem with the server.

When UDP is used as a transport protocol, the absence of a reply can cause a client to deduce (incorrectly) that the proxy is unavailable.
The client could then fail over to another server or conclude that no "live" servers are available (OKAY state in {{!RFC3539}}, Appendix A).
This situation is made even worse when requests are sent through a proxy to multiple destinations.
Failures in one destination may result in service outages for other destinations, if the client erroneously believes that the proxy is unresponsive.

For RADIUS/TLS, it is RECOMMENDED that implementations utilize the existence of a TCP connection along with the application-layer watchdog defined in {{RFC3539}}, Section 3.4 to determine that the server is "live".
RADIUS/TLS clients MUST mark a connection DOWN, if the network stack indicates that the connection is no longer active.
If the network stack indicates that the connection is still active, clients MUST NOT decide that it is down until the application-layer watchdog algorithm has marked it DOWN.
RADIUS/TLS clients MUST NOT decide that a RADIUS/TLS server is unresponsive until all TLS connections to it have been marked down.[^contradiction]{:jf}

[^contradiction]: The specification in RFC6613 is contradictory here. Section 2.4 says that it is recommended to have a watchdog. Section 2.6 says it must be used.

The above requirements do not forbid the practice of a client proactively closing connections or marking a server as DOWN due to an administrative decision.

It is RECOMMENDED that RADIUS/(D)TLS nodes implement the Status-Server extension as described in {{?RFC5997}} to detect the liveness of the peer without dependence on successful authentications.
Since RADIUS has a limitation of 256 simultaneous "in flight" packets due to the length of the ID field ({{RFC3539}}, Section 2.4), it is RECOMMENDED that RADIUS/(D)TLS clients reserve ID zero (0) on each session for Status-Server packets.
This value was picked arbitrary, as there is no reason to choose any other value over another for this use.[^statusserver]{:jf}

[^statusserver]: TODO: RFC6613 mandates the use of Status-Server for RADIUS/TCP, RFC7360 only recommends it for RADIUS/DTLS. Maybe it should be mandatory for both?

# Packet / Connection Handling

This section defines the behaviour for RADIUS/(D)TLS peers for handling of incoming packets and establishment of a (D)TLS session

## (D)TLS requirements

[^src_6614_2_3]

[^src_6614_2_3]: Source: Mainly RFC6614, Section 2.3, Items 1 and 2, but without peer authentication models (in next section) or unnecessary text (e.g. MTI cipher suites, we just rely on the TLS cipher suites. Maybe explicitly mention that the MTI ciphers from TLS are also mandatory for this?)

As defined in {{portusage}}, RAIDUS/(D)TLS clients must establish a (D)TLS session immediately upon connecting to a new server.

RADIUS/(D)TLS has no notion of negotiating (D)TLS in an ongoing communication.
As RADIUS has no provisions for capability signaling, there is also no way for a server to indicate to a client that it should transition to using TLS or DTLS.
Servers and clients need to be preconfigured to use RADIUS/(D)TLS for a given endpoint.
This action has to be taken by the administrators of the two systems.

The following requirements have to be met for the (D)TLS session:

* Support for TLS 1.2 {{!RFC5248}} / DTLS 1.2 {{!RFC6347}} is REQUIRED, support for TLS 1.3 {{!RFC8446}} / DTLS 1.3 {{!RFC9147}} or higher is RECOMMENDED.
* Negotiation of a cipher suite providing for confidentiality as well as integrity protection is REQUIRED.
* The peers MUST NOT negotiate compression.
* The session MUST be mutually authenticated (see {{mutual_auth}})

## Mutual authentication
{: #mutual_auth }

[^src_6614_2_3_item3]

[^src_6614_2_3_item3]: Source: RFC6614, Section 2.3, Item 3 with modifications.

RADIUS/(D)TLS servers MUST authenticate clients.
RADIUS is designed to be used by mutually trusted systems.
Allowing anonymous clients would ensure privacy for RADIUS/(D)TLS traffic, but would negate all other security aspects of the protocol.

RADIUS/(D)TLS allows for the following different modes of mutual authentication.

### Authentication using X.509 certificates with PKIX trust model

All RADIUS/(D)TLS implementations MUST implement this model, with the following rules:

* Implementations MUST allow the configuration of a list of trusted Certificate Authorities for new TLS sessions.
* Certificate validation MUST include the verification rules as per {{!RFC5280}}.
* Implementations SHOULD indicate their trusted Certification authorities (CAs).
  See {{!RFC5246}}, Section 7.4.4 and {{!RFC6066}}, Section 6 for TLS 1.2 and {{!RFC8446}}, Section 4.2.4 for TLS 1.3 [^dtls-ca-ind]{:jf}
* RADIUS/(D)TLS clients validate the servers identity to match their local configuration:
  - If the expected RADIUS/(D)TLS server was configured as a hostname, the configured name is matched against the presented names from the subjectAltName:DNS extension; if no such exist, against the presented CN component of the certificate subject
  - If the expected RADIUS/(D)TLS server was configured as an IP address, the configured IP address is matched against the presented addresses in the subjectAltName:iPAddr extension; if no such exist, against the presented CN component of the certificate subject.
  - If the RADIUS/(D)TLS server was not configured but discovered as per {{!RFC7585}}, the client executes the following checks in this order, accepting the certificate on the first match:
    * The realm which was used as input to the discovery is matched against the presented realm names from the subjectAltName:naiRealm extension.
    * If the discovery process yielded a hostname, this hostname is matched against the presented names from the subjectAltName:DNS extension; if no such exist, against the presented CN component of the certificate subject.
      Implementations MAY require the use of DNSSEC {{!RFC4033}} to ensure the authenticity of the DNS result before relying on this for trust checks.
    * If the previous checks fail, the certificate MAY Be accepted without further name checks immediately after the {{RFC5280}} trust chain checks, if configured by the administrator.
* RADIUS/(D)TLS servers validate the certificate of the RADIUS/(D)TLS client against a local database of acceptable clients.
  The database may enumerate acceptable clients either by IP address or by a name component in the certificate
  * For clients configured by name, the configured name is matched against the presented names from the subjectAltName:DNS extension; if no such exist, against the presented CN component in the certificate subject.
  * For clients configured by their source IP address, the configured IP address is matched against the presented addresses in the subjectAltName:iPAddr extension; if no such exist, against the presented CN component of the certificate subject. [^ipaddr-cidr]{:jf}
  * It is possible for a RADIUS/(D)TLS server to not require additional name checks for incoming RADIUS/(D)TLS clients, i.e. if the client used dynamic lookup.
    In this case, the certificate is accepted immediately after the {{RFC5280}} trust chain checks.
    This MUST NOT be used outside of trusted network environments or without additional certificate attribute checks in place.
* Implementations MAY allow a configuration of a set of additional properties of the certificate to check for a peer's authorization to communicate (e.g. a set of allowed values in subjectAltName:URI or a set of allowed X.509v3 Certificate Policies).
* When the configured trust base changes (e.g., removal of a CA from the list of trusted CAs; issuance of a new CRL for a given CA), implementations SHOULD renegotiate the TLS session to reassess the connecting peer's continued authorization.[^may-should-trustbase]{:jf}

[^dtls-ca-ind]: TODO: CA-Indication for DTLS.
[^ipaddr-cidr]: TODO: Find out if there are matching rules for subnet configuration.
[^may-should-trustbase]: Open discussion: RFC6614 says "may" here. I think this should be a "should".

### Authentication using X.509 certificate fingerprints

RADIUS/(D)TLS implementations SHOULD allow the configuration of a list of trusted certificates, identified via fingerprint of the DER encoded certificate bytes.
When implementing this model, support for SHA-1 as hash algorithm for the fingerprint is REQUIRED, and support for the more contemporary hash function SHA-256 is RECOMMENDED.

### Authentication using Raw Public Keys

RADIUS/(D)TLS implementations SHOULD support using Raw Public Keys {{!RFC7250}} for mutual authentication.

### Authentication using TLS-PSK

RADIUS/(D)TLS implementations SHOULD support the use of TLS-PSK.
Further guidance on the usage of TLS-PSK in RADIUS/(D)TLS is given in {{!I-D.ietf-radext-tls-psk}}.

## Connecting Client Identity

[^src_6614_2_4]

[^src_6614_2_4]: Source: RFC6614, Section 2.4 with small modifications

In RADIUS/UDP, clients are uniquely identified by their IP addresses.
Since the shared secret is associated with the origin IP address, if more than one RADIUS client is associated with the same IP address, then those clients also must utilize the same shared secret, a practice that is inherently insecure, as noted in {{!RFC5247}}.

Depending on the operation mode, the RADIUS/(D)TLS client identity can be determined differently.

In TLS-PSK operation, a client is uniquely identified by its TLS-PSK identifier.[^pskid]{:jf}

In Raw-Public-Key operation, a client is uniquely identified by the Raw public key.

In TLS-X.509 mode using fingerprints, a client is uniquely identified by the fingerprint of the presented client certificate.

In TLS-X.509 mode using PKIX trust models, a client is uniquely identified by the tuple of the serial number of the presented client certificate and the issuer.

Note well: having identified a connecting entity does not mean the server necessarily wants to communicate with that client.
For example, if the Issuer is not in a trusted set of Issuers, the server may decline to perform RADIUS transactions with this client.

There are numerous trust models in PKIX environments, and it is beyond the scope of this document to define how a particular deployment determines whether a client is trustworthy.
Implementations that want to support a wide variety of trust models should expose as many details of the presented certificate to the administrator as possible so that the trust model can be implemented by the administrator.
As a suggestion, at least the following parameters of the X.509 client certificate should be exposed:

* Originating IP address
* Certificate Fingerprint
* Issuer
* Subject
* all X.509v3 Extended Key Usage
* all X.509v3 Subject Alternative Name
* all X.509v3 Certificate Policy

In TLS-PSK operation at least the following parameters of the TLS connection should be exposed:

* Originating IP address
* TLS-PSK Identifier

[^pskid]: TODO: What is the correct term here? "PSK Identifier"? Probably not "TLS Identifier" as it was in RFC6614

## RADIUS Datagrams

[^src_6614_2_5]

[^src_6614_2_5]: Source: RFC 6614, Section 2.5 with small modifications and without example list


RADIUS/(D)TLS clients transmit the same packet types on the connection they initiated as a RADIUS/UDP client would, RADIUS/(D)TLS servers transmit the same packet types on the connections they have accepted as a RADIUS/UDP server would.

Due to the use of one single port for all packet types, it is required that a RADIUS/(D)TLS server signals which types of packets are supported on a server to a connecting peer.

* When an unwanted packet of type 'CoA-Request' or 'Disconnect-Request' is received, a RADIUS/(D)TLS server needs to respond with a 'CoA-NAK' or 'Disconnect-AK', respectively.
  The NAK SHOULD contain an attribute Error-Cause with the value 406 ("Unsupported Extension"); see {{!RFC5176}} for details.
* When an unwanted packet of type 'Accounting-Request' is received, the RADIUS/(D)TLS server SHOULD reply with an Accounting-Response containing an Error-Cause attribute with value 406 "Unsupported Extensions" as defined in {{RFC5176}}.
  A RADIUS/(D)TLS accounting client receiving such an Accounting-Response SHOULD log the error and stop sending Accounting-Request packets.

# RADIUS/TLS specific specifications

This section discusses all specifications that are only relevant for RADIUS/TLS.

## Duplicates and Retransmissions

[^src_6613_2_6_1]

[^src_6613_2_6_1]: Source: RFC6613, Section 2.6.1, with small modifications

As TCP is a reliable transport, RADIUS/TLS peers MUST NOT retransmit RADIUS packets over a given TCP connection.
Similarly, if there is no response to a RADIUS packet over one RADIUS/TLS connection, implementations MUST NOT retransmit that packet over a different connection to the same destination IP address and port, while the first connection is in the OKAY state ({{RFC3539, Appendix A}}.

However, if the TLS session or TCP connection is closed or broken, retransmissions over new connections are permissible.
RADIUS request packets that have not yet received a response MAY be transmitted by a RADIUS/TLS client over a new connection.
As this procedure involves using a new source port, the ID of the packet MAY change.
If the ID changes, any security attributes such as Message-Authenticator MUST be recalculated.

If a TLS session or the underlying TCP connection is closed or broken, any cached RADIUS response packets ({{!RFC5080, Section 2.2.2}}) associated with that connection MUST be discarded.
A RADIUS server SHOULD stop the processing of any requests associated with that TLS session.
No response to these requests can be sent over the TLS connection, so any further processing is pointless.
This requirement applies not only to RADIUS servers, but also to proxies.
When a client's connection to a proxy is closed, there may be responses from a home server that were supposed to be sent by the proxy back over that connection to the client.
Since the client connection is closed, those responses from the home server to the proxy server SHOULD be silently discarded by the proxy.

Despite the above discussion, RADIUS servers SHOULD still perform duplicate detection on received packets, as described in {{RFC5080, Section 2.2.2}}.
This detection can prevent duplicate processing of packets from non-conforming clients.

RADIUS packets SHOULD NOT be retransmitted to the same destination IP an numerical port, but over a different transport protocol.
There is no guarantee in RADIUS that the two ports are in any way related.
This requirement does not, however, forbid the practice of putting multiple servers into a failover or load-balancing pool.
In that situation, RADIUS requests MAY be retransmitted to another server that is known to be part of the same pool.

## Malformed Packets and Unknown clients

[^src_6613_2_6_4]

[^src_6613_2_6_4]: Source: RFC 6613, Section 2.6.4 with small modifications.

The RADIUS specifications say that an implementation should "silently discard" a packet in a number of circumstances.
This action has no further consequences for UDP based transports, as the "next" packet is completely independent of the previous one.

When TLS is used as transport, decoding the "next" packet on a connection depends on the proper decoding of the previous packet.
As a result the behavior with respect to discarded packets has to change.

Implementations of this specification SHOULD tread the "silently discard" texts in the RADIUS specification referenced above as "silently discard and close the connection".
That is, the implementation SHOULD send a TLS close notification and the underlying TCP connection MUST be closed if any of the following circumstances are seen:

* Connection from an unknown client
* Packet where the RADIUS "Length" field is less than the minimum RADIUS packet length
* Packet where the RADIUS "Length" field is more than the maximum RADIUS packet length
* Packet where an Attribute "Length" field has the value of zero or one (0 or 1)
* Packet where the attributes do not exactly fill the packet
* Packet where the Request Authenticator fails validation (where validation is required)
* Packet where the Response Authenticator fails validation (where validation is required)
* Packet where the Message-Authenticator attribute fails validation (when it occurs in a packet)

After applying the above rules, there are still two situations where the previous specifications allow a packet to be "silently discarded" upon receipt:

* Packet with an invalid code field
* Response packets that do not match any outstanding request

In these situations, the TCP connections MAY remain open, or they MAY be closed, as an implementation choice. However, the invalid packet MUST be silently discarded.

These requirements reduce the possibility for a misbehaving client or server to wreak havoc on the network.

## TCP Applications Are Not UDP Applications

[^src_6613_2_6_2]

[^src_6613_2_6_2]: Source: RFC6613, Section 2.6.7 (TCP != UDP) and Section 2.6.2 (HoL-Blocking) with small modifications

Implementors should be aware that programming a robust TCP-based application can be very different from programming a robust UDP-based application.

Implementations SHOULD have configurable connection limits, configurable limits on connection lifetime and idle timeouts and a configurable rate limit on new connections.
Allowing an unbounded number or rate of TCP/TLS connections may result in resource exhaustion.

Additionally, differences in the transport like Head of Line (HoL) blocking should be considered.

When using RADIUS/UDP or RADIUS/DTLS, there is no ordering of packets.
If a packet sent by a peer is lost, that loss has no effect on subsequent packets sent by that peer.

Unlike UDP, TCP is subject to issues related to Head of Line blocking.
This occurs when a TCP segment is lost and a subsequent TCP segment arrives out of order.
While the RADIUS peers can process RADIUS packets out of order, the semantics of TCP makes this impossible.
This limitation can lower the maximum packet processing rate of RADIUS/TLS.

# RADIUS/DTLS specific specifications
{: #dtls_spec }

This section discusses all specifications that are only relevant for RADIUS/DTLS.

## RADIUS packet lengths

[^src_7360_2_1]

[^src_7360_2_1]: Source: RFC7360, Section 2.1, last paragraphs

The DTLS encryption adds an additional overhead to each packet sent.
RADIUS/DTLS implementations MUST support sending and receiving RADIUS packets of 4096 bytes in length, with a corresponding increase in the maximum size of the encapsulated DTLS packets.
This larger packet size may cause the packet to be larger than the Path MTU (PMTU), where a RADIUS/UDP packet may be smaller.

The Length checks defined in {{RFC2865, Section 3}} MUST use the length of the decrypted DTLS data instead of the UDP packet length.
They MUST treat any decrypted DTLS data bytes outside the range of the length field as padding and ignore it on reception.

## Server behavior

[^src_7360_3_2]

[^src_7360_3_2]: Source: RFC7360, Section 3.2 with small modifications

When a RADIUS/DTLS server receives packets on the configured RADIUS/DTLS port, all packets MUST be treated as being DTLS.
RADIUS/UDP packets MUST NOT be accepted on this port.

Some servers maintain a list of allowed clients per destination port.
Others maintain a global list of clients that are permitted to send packets to any port.
Where a client can send packets to multiple ports, the server MUST maintain a "DTLS Required" flag per client.

This flag indicates whether or not the client is required to use DTLS.
When set, the flag indicates that the only traffic accepted from the client is over the RADIUS/DTLS port.
When packets are received fom a client with the "DTLS Required" flag set on non-DTLS ports, the server MUST silently discard these packets, as there is no RADIUS/UDP shared secret available.

This flag will often be set by an administrator.
However, if the server receives DTLS traffic from a client, it SHOULD notify the administrator that DTLS is available for that client.
It MAY mark the client as "DTLS Required".

Allowing RADIUS/UDP and RADIUS/DTLS from the same client exposes the traffic to downbidding attacks and is NOT RECOMMENDED.

## Client behavior

[^src_7360_4]

[^src_7360_4]: Source: RFC7360, Section 4

When a RADIUS/DTLS client sends packet to the assigned RADIUS/DTLS port, all packets MUST be DTLS.
RADIUS/UDP packets MUST NOT be sent to this port.

RADIUS/DTLS clients SHOULD NOT probe servers to see if they support DTLS transport.
Instead, clients SHOULD use DTLS as a transport layer only when administratively configured.
If a client is configured to use DTLS and the server appears to be unresponsive, the client MUST NOT fall back to using RADIUS/UDP.
Instead, the client should treat the server as being down.

RADIUS clients often had multiple independent RADIUS implementations and/or processes that originate packets.
This practice was simple to implement, but the result is that each independent subsystem must independently discover network issues or server failures.
It is therefore RECOMMENDED that clients with multiple internal RADIUS sources use a local proxy.

Clients may implement "pools" of servers for fail-over or load-balancing.
These pools SHOULD NOT mix RADIUS/UDP and RADIUS/DTLS servers.[^movetogeneral]{:jf}

[^movetogeneral]: This paragraph should probably be moved, as it also applies to RADIUS/TLS. Mixing secure transports with insecure ones is bad practice, regardless of UDP or TCP.

## Session Management

[^src_7350_5]

[^src_7350_5]: Source; RFC7360, Section 5

Where RADIUS/TLS can rely on the TCP state machine to perform session tracking, RADIUS/DTLS cannot.
As a result, implementations of RADIUS/DTLS may need to perform session management of the DTLS session in the application layer.
This subsection describes logically how this tracking is done.
Implementations may choose to use the method described here, or another, equivalent method.

We note that {{RFC5080, Section 2.2.2}}, already mandates a duplicate detection cache.
The session tracking described below can be seen as an extension of that cache, where entries contain DTLS sessions instead of RADIUS/UDP packets.

{{RFC5080, Section 2.2.2}}, describes how duplicate RADIUS/UDP requests result in the retransmission of a previously cached RADIUS/UDP response.
Due to DTLS sequence window requirements, a server MUST NOT retransmit a previously sent DTLS packet.
Instead, it should cache the RADIUS response packet, and re-process it through DTLS to create a new RADIUS/DTLS packet, every time it is necessary to retransmit a RADIUS response.

[^movespecfromclsrvhere]{:jf}

[^movespecfromclsrvhere]: There are some specs (e.g. watchdog, stateless session resumption, closing session if malformed packet or security checks fail) which are valid for both server and client. It might be worth to just move them here instead of having them in both the client and the server spec.

### Server Session Management

[^src_7360_5_1]

[^src_7360_5_1]: Source: RFC7360, Section 5.1

A RADIUS/DTLS server MUST track ongoing DTLS sessions for each client, based on the following 4-tuple:

* source IP address
* source port
* destination IP address
* destination port

Note that this 4-tuple is independent of IP address version (IPv4 or IPv6).

Each 4-tuple points to a unique session entry, which usually contains the following information:

DTLS Session:
: Any information required to maintain and manage the DTLS session.

Last Traffic:
: A variable containing a timestamp that indicates when this session last received valid traffic.
If "Last Traffic" is not used, this variable may not exist.

DTLS Data:
: An implementation-specific variable that may contain information about the active DTLS session.
This variable may be empty or nonexistent.

: This data will typically contain information such as idle timeouts, session lifetimes, and other implementation-specific data.

#### Session Opening and Closing

[^src_7360_5_1_1]

[^src_7360_5_1_1]: Source: RFC7360, Section 5.1.1 with small modifications

Session tracking is subject to Denial-of-Service (DoS) attacks due to the ability of an attacker to forge UDP traffic.
RADIUS/DTLS servers SHOULD use the stateless cookie tracking technique described in {{!RFC6347, Section 4.2.1}}.
DTLS sessions SHOULD NOT be tracked until a ClientHello packet has been received with an appropriate Cookie value.
Server implementation SHOULD have a way of tracking DTLS sessions that are partially set up.
Servers MUST limit both the number and impact on resources of partial sessions.

Sessions (both 4-tuple and entry) MUST be deleted when a TLS Closure Alert ({{RFC5246, Section 7.2.1}}) or a fatal TLS Error Alert ({{RFC5246, Section 7.2.2}}) is received.
When a session is deleted due to it failing security requirements, the DTLS session MUST be closed, any TLS session resumption parameters for that session MUST be discarded, and all tracking information MUST be deleted.

Sessions MUST also be deleted when a non-RADIUS packet is received, a RADIUS packet fails validation due to a packet being malformed, or when it has an invalid Message-Authenticator or invalid Request Authenticator.
There are other cases when the specifications require that a packet received via a DTLS session be "silently discarded".
In those cases, implementations MAY delete the underlying session as described above.
A session SHOULD NOT be deleted when a well-formed, but "unexpected", RADIUS packet is received over it.

These requirements ensure the security while maintaining flexibility.
Any security-related issue causes the connection to be closed.
After security restrictions have been applied, any unexpected traffic may be safely ignored, as it cannot cause a security issue.
This allows for future extensions to the RADIUS/DTLS specifications.

Once a DTLS session is established, a RADIUS/DTLS server SHOULD use DTLS Heartbeats {{!RFC6520}} to determine connectivity between the two servers.
A server SHOULD also use watchdog packets from the client to determine that the session is still active.

As UDP does not guarantee delivery of messages, RADIUS/DTLS servers that do not implement an application-layer watchdog MUST also maintain a "Last Traffic" timestamp per DTLS session.
The granularity of this timestamp is not critical and could be limited to one-second intervals.
The timestamp SHOULD be updated on reception of a valid RADIUS/DTLS packet, or a DTLS Heartbeat, but no more than once per interval.
The timestamp MUST NOT be updated in other situations.

When a session has not received a packet for a period of time, it is labeled "idle".
The server SHOULD delete idle DTLS sessions after an "idle timeout".
The server MAY cache the TLS session parameters, in order to provide for fast session resumption.[^idle-timeout-conf]{:jf}

[^idle-timeout-conf]: RFC 7360 adds a paragraph about that the idle timeout should not be exposed to the admin as configurable parameter and references a mechanism to determine this value from the application-layer watchdog, but I didn't find the specification anywhere.

RADIUS/DTLS servers SHOULD also monitor the total number of open sessions.
They SHOULD have a "maximum sessions" setting exposed to administrators as a configurable parameter.
When this maximum is reached and a new session is started, the server MUST either drop an old session in order to open the new one or not create a new session.

RADIUS/DTLS servers SHOULD implement session resumption, preferably stateless session resumption as given in {{!RFC5077}}.
This practice lowers the time and effort required to start a DTLS session with a client and increases network responsiveness.

Since UDP is stateless, the potential exists for the client to initiate a new DTLS session using a particular 4-tuple, before the server has closed the old session.
For security reasons, the server MUST keep the old session active until either it has received secure notification from the client that the session is closed or the server decides to close the session based on idle timeouts.
Taking any other action would permit unauthenticated clients to perform a DoS attack, by reusing a 4-tuple and thus causing the server to close an active (and authenticated) DTLS session.

As a result, servers MUST ignore any attempts to reuse an existing 4-tuple from an active session.
This requirement can likely be reached by simply processing the packet through the existing session, as with any other packet received via that 4-tuple.
Non-compliant, or unexpected packets will be ignored by the DTLS layer.[^proxymitigation]{:jf}

[^proxymitigation]: In RFC7360 there is a final paragraph about mitigation of the 4-tuple problem by using a local proxy. I'm not sure if this is the right place here, i'd rather move that to a general "Implementation Guidelines" paragraph.

### Client Session Management

[^src_7360_5_2]

[^src_7360_5_2]: Source: RFC7360, Section 5.2 with modifications

RADIUS/DTLS clients SHOULD use PMTU discovery {{!RFC6520}} to determine the PMTU between the client and server, prior to sending any RADIUS traffic.
Once a DTLS session is established, a RADIUS/DTLS client SHOULD use DTLS Heartbeats {{RFC6520}} to determine connectivity between the two systems.
RADIUS/DTLS clients SHOULD also use the application-layer watchdog algorithm defined in {{RFC3539}} to determine server responsiveness.
The Status-Server packet defined in {{RFC5997}} SHOULD be used as the "watchdog packet" in any application-layer watchdog algorithm.[^doublespec]{:jf}

[^doublespec]: The Status-Server spec was already mentioned above. Maybe remove it from here?

RADIUS/DTLS clients SHOULD proactively close sessions when they have been idle for a period of time.
Clients SHOULD close a session when the DTLS Heartbeat algorithm indicates that the session is no longer active.
Clients SHOULD close a session when no traffic other than watchdog packet and (possibly) watchdog responses have been sent for three watchdog timeouts.
This behavior ensures that clients do not wast resources on the server by causing it to track idle sessions.

When a client fails to implement both DTLS Heartbeats and watchdog packets, it has no way of knowing that a DTLS session has been closed.
Therefore, there is the possibility that the server closes the session without the client knowing.
When that happens, the client may later transmit packets in a session, and those packets will be ignored by the server.
The client is then forced to time out those packets and then the session, leading to delays and network instabilities.

For these reasons, it is RECOMMENDED that all DTLS session be configured to use DTLS Heartbeats and/or watchdog packets.

DTLS sessions MUST also be deleted when a RADIUS packet fails validation due to a packet being malformed, or when it has an invalid Message-Authenticator or invalid Response Authenticator.
There are other cases, when the specifications require that a packet received via a DTLS session be "silently discarded".
In those cases, implementations MAY delete the underlying DTLS session.

RADIUS/DTLS clients SHOULD NOT send both RADIUS/UDP and RADIUS/DTLS packets to different servers from the same source socket.
This practice causes increased complexity in the client application and increases the potential for security breaches due to implementation issues.

RADIUS/DTLS clients SHOULD implement session resumption, preferably stateless session resumption as given in {{RFC5077}}.
This practice lowers the time and effort required to start a DTLS session with a server and increases network responsiveness.

# Security Considerations

TODO Security


# IANA Considerations

Upon approval, IANA should update the Reference to radsec in the Service Name and Transport Protocol Port Number Registry:

* Service Name: radsec
* Port Number: 2083
* Transport Protocol: tcp/udp
* Description: Secure RADIUS Service
* Assignment notes: The TCP port 2083 was already previously assigned by IANA for "RadSec", an early implementation of RADIUS/TLS, prior to issuance of the experimental RFC 6614.
  [This document] updates RFC 6614 (RADIUS/TLS) and RFC 7360 (RADIUS/DTLS), while maintaining backward compatibility, if configured. For further details see RFC 6614, Appendix A or [This document] {{backwardcomp}}.

--- back

# Lessens learned from deployments of the Experimental {{RFC6614}}

There are at least to major (world-scale deployments of {{RFC6614}}.
This section will discuss lessens learned from these deployments, that influenced this document.

## eduroam

eduroam is a globally operating Wi-Fi roaming consortium exclusively for persons in Research and Education. For an extensive background on eduroam and its authentication fabric architecture, refer to {{?RFC7593}}.

Over time, more than a dozen out of 100+ national branches of eduroam used RADIUS/TLS in production to secure their country-to-country RADIUS proxy connections. This number is big enough to attest that the protocol does work, and scales. The number is also low enough to wonder why RADIUS/UDP continued to be used by a majority of country deployments despite its significant security issues.

Operational experience reveals that the main reason is related to the choice of PKIX certificates for securing the proxy interconnections. Compared to shared secrets, certificates are more complex to handle in multiple dimensions:

* Lifetime: PKIX certificates have an expiry date, and need administrator attention and expertise for their renewal
* Validation: The validation of a certificate (both client and server) requires contacting a third party to verify the revocation status. This either takes time during session setup (OCSP checks) or requires the presence of a fresh CRL on the server - this in turn requires regular update of that CRL.
* Issuance: PKIX certificates carry properties in the Subject and extensions that need to be vetted. Depending on the CA policy, a certificate request may need significant human intervention to be verified. In particular, the authorisation of a requester to operate a server for a particular NAI realm needs to be verified. This rules out public "browser-trusted" CAs; eduroam is operating a special-purpose CA for eduroam RADIUS/TLS purposes.
* Automatic failure over time: CRL refresh and certificate renewal must be attended to regularly. Failure to do so leads to failure of the authentication service. Among other reasons, employee churn with incorrectly transferred or forgotten responsibilities is a risk factor.

It appears that these complexities often outweigh the argument of improved security; and a fallback to RADIUS/UDP is seen as the more appealing option.

It can be considered an important result of the experiment in {{RFC6614}} that providing less complex ways of operating RADIUS/TLS are required. The more thoroughly specified provisions in the current document towards TLS-PSK and raw public keys are a response to this insight.

On the other hand, using RADIUS/TLS in combination with Dynamic Discovery as per {{RFC7585}} necessitates the use of PKIX certificates. So, the continued ability to operate with PKIX certificates is also important and cannot be discontinued without sacrificing vital functionality of large roaming consortia.

## Wireless Broadband Alliance's OpenRoaming

OpenRoaming is a globally operating Wi-Fi roaming consortium for the general public, operated by the Wireless Broadband Alliance (WBA). With its (optional) settled usage of hotspots, the consortium requires both RADIUS authentication as well as RADIUS accounting.

The consortium operational procedures were defined in the late 2010s when {{RFC6614}} and {{RFC7585}} were long available. The consortium decided to fully base itself on these two RFCs.

In this architecture, using PSKs or raw public keys is not an option. The complexities around PKIX certificates as discussed in the previous section are believed to be controllable: the consortium operates its own special-purpose CA and can rely on a reliable source of truth for operator authorisation (becoming an operator requires a paid membership in WBA); expiry and revocation topics can be expected to be dealt with as high-priority because of the monetary implications in case of infrastructure failure during settled operation.

## Participating in more than one roaming consortium

It is possible for a RADIUS/TLS (home) server to participate in more than one roaming consortium, i.e. to authenticate its users to multiple clients from distinct consortia, which present client certificates from their respective consortium's CA; and which expect the server to present a certificate from the matching CA.

The eduroam consortium has chosen to cooperate with (the settlement-free parts of) OpenRoaming to allow eduroam users to log in to (settlement-free) OpenRoaming hotspots.

eduroam RADIUS/TLS servers thus may be contacted by OpenRoaming clients expecting an OpenRoaming server certificate, and by eduroam clients expecting an eduroam server certificate.

It is therefore necessary to decide on the certificate to present during TLS session establishment. To make that decision, the availability of Trusted CA Indication in the client TLS message is important.

It can be considered an important result of the experiment in {{RFC6614}} that Trusted CA Indication is an important asset for inter-connectivity of multiple roaming consortia.

# Interoperable Implementations

# Backward compatibility
{: #backwardcomp}

TODO describe necessary steps to configure common servers for compatibility with this version.
Hopefully the differences to {{RFC6614}} are small enough that almost no config change is necessary.

# Acknowledgments
{:numbered="false"}

Thanks to the original authors of RFC 6613, RFC 6614 and RFC 7360: Alan DeKok, Stefan Winter, Mike McCauley, Stig Venaas and Klaas Vierenga.
