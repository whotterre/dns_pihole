package entities

type DNSHeader struct {
	ID uint16
	Flags uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}