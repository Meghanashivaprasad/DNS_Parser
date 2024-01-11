package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type DNSHeader struct {
	ID       uint16
	Flags    uint16
	QDCount  uint16
	ARCount  uint16
	AURCount uint16
	ADRCount uint16
}
type DNSQuestion struct {
	QName  string
	QType  uint16
	QClass uint16
}
type DNSAnswer struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RLen  uint16
	RData []byte
}

func handler_parse_DNS_payload(packet gopacket.Packet) {
	transportLayer := packet.TransportLayer()
	payload := transportLayer.LayerPayload()
	header := DNSHeader{
		ID: binary.BigEndian.Uint16(payload[0:2]),

		Flags:    binary.BigEndian.Uint16(payload[2:4]),
		QDCount:  binary.BigEndian.Uint16(payload[4:6]),
		ARCount:  binary.BigEndian.Uint16(payload[6:8]),
		AURCount: binary.BigEndian.Uint16(payload[8:10]),
		ADRCount: binary.BigEndian.Uint16(payload[10:12]),
	}
	fmt.Printf("DNS Header:\nID: %d\nFlags: %d\nQDCount: %d\nANCount: %d\nNSCount: %d\nARCount: %d\n",
		header.ID, header.Flags, header.QDCount, header.ARCount, header.AURCount, header.ADRCount)
	// Skip the DNS header
	offset := 12

	// Parse questions
	fmt.Println("\nDNS Questions:")
	for i := 0; i < int(header.QDCount); i++ {
		question, newOffset := parseQuestion(payload, offset)
		fmt.Printf("QName: %s\nQType: %d\nQClass: %d\n", question.QName, question.QType, question.QClass)
		offset = newOffset
	}

	// Parse answers
	fmt.Println("\nDNS Answers:")
	for i := 0; i < int(header.ARCount); i++ {
		answer, newOffset := parseAnswer(payload, offset)
		fmt.Printf("Name: %s\nType: %d\nClass: %d\nTTL: %d\nRDLen: %d\nRData: %d\n",
			answer.Name, answer.Type, answer.Class, answer.TTL, answer.RLen, answer.RData)
		offset = newOffset
	}
}

func parseQuestion(payload []byte, offset int) (DNSQuestion, int) {
	qname, newOffset := parseName(payload, offset)
	question := DNSQuestion{
		QName:  qname,
		QType:  binary.BigEndian.Uint16(payload[newOffset : newOffset+2]),
		QClass: binary.BigEndian.Uint16(payload[newOffset+2 : newOffset+4]),
	}
	return question, newOffset + 4
}

func parseAnswer(payload []byte, offset int) (DNSAnswer, int) {
	name, newOffset := parseName(payload, offset)
	answer := DNSAnswer{
		Name:  name,
		Type:  binary.BigEndian.Uint16(payload[newOffset : newOffset+2]),
		Class: binary.BigEndian.Uint16(payload[newOffset+2 : newOffset+4]),
		TTL:   binary.BigEndian.Uint32(payload[newOffset+4 : newOffset+8]),
		RLen:  binary.BigEndian.Uint16(payload[newOffset+8 : newOffset+10]),
		RData: payload[newOffset+10 : newOffset+10+int(binary.BigEndian.Uint16(payload[newOffset+8:newOffset+10]))],
	}
	return answer, newOffset + 10 + int(answer.RLen)
}

func parseName(payload []byte, offset int) (string, int) {
	var name string
	for {
		length := int(payload[offset])
		if length == 0 {
			break
		}
		if length&0xC0 == 0xC0 {
			// Compressed name
			pointer := binary.BigEndian.Uint16([]byte{payload[offset] & 0x3F, payload[offset+1]})
			namePart, _ := parseName(payload, int(pointer))
			name += namePart
			offset += 2
			break
		}
		name += string(payload[offset+1:offset+1+length]) + "."
		offset += 1 + length
	}
	return name, offset + 1
}

func handler_for_packet(packet gopacket.Packet) {
	// Extract relevant information from the packet
	networkLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()

	if networkLayer != nil {
		srcIP := networkLayer.NetworkFlow().Src().String()
		dstIP := networkLayer.NetworkFlow().Dst().String()

		// Check if the packet is TCP or UDP

		var srcPort, dstPort string
		if transportLayer != nil {
			if transportLayer.LayerType() == layers.LayerTypeUDP {
				if udpLayer, ok := transportLayer.(*layers.UDP); ok {
					if udpLayer.DstPort == 53 || udpLayer.SrcPort == 53 {
						fmt.Println("this is UDP packet\n")
						fmt.Printf("Source IP: %s\n", srcIP)
						fmt.Printf("Destination IP: %s\n", dstIP)
						srcPort = udpLayer.TransportFlow().Src().String()
						dstPort = udpLayer.TransportFlow().Dst().String()
						fmt.Printf("Source Port: %s\n", srcPort)
						fmt.Printf("Destination Port: %s\n", dstPort)
						handler_parse_DNS_payload(packet)
						fmt.Println(strings.Repeat("=", 40))
					}
				}
			}
		}

	}
}

func sniffer(device string) {
	handle, err := pcap.OpenLive(device, 1600, true, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		handler_for_packet(packet)
	}

}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("use go run packet_sniffer.go <Network Interface>")
		os.Exit(1)
	}
	networkInterface := os.Args[1]
	fmt.Println("we are starting the packet sniffer %s\n", networkInterface)
	sniffer(networkInterface)
}
