package entities

/* 
This contains:
- The ID - a random number that uniquely identifies the header
- The Flag fields which contain:
* The QR field: 0 (for query), 1 (for response)
* The Opcode (of which only 0-2 are concrete)
* The AA (Authoritative Answer) - This bit is valid in responses,
                and specifies that the responding name server is an
                authority for the domain name in question section.
* The TC (Truncation bit) - Set if the the message was truncated.const
* The RD (Recursion Desired) - If set, it directs the name server to pursue the query recursively.
* The RA (Recursion Available) - Set or cleared in a
                response, and denotes whether recursive query support is
                available in the name server.

* The QdCount - Stores number of the entries in the question section.
* The AnCount - Stores number of records in the answer section.
* The ArCount - Stores number of resource records in the additional records section.
* The NsCount - Stores number of number of nameserver resource records in the authority records section.

*/
type DNSHeader struct {
	ID      uint16 // Random number
	Flags   uint16 // Contains the QR (1 bit), Opcode (4 bits), [AA, TC, RD, RA (1 bit) ,
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}
