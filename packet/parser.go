// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package packet

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/apex/log"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/security-onion-solutions/securityonion-soc/model"
)

var SupportedLayerTypes = [...]gopacket.LayerType{
	layers.LayerTypeARP,
	layers.LayerTypeDHCPv4,
	layers.LayerTypeDHCPv6,
	layers.LayerTypeDNS,
	layers.LayerTypeICMPv4,
	layers.LayerTypeICMPv6,
	layers.LayerTypeIGMP,
	layers.LayerTypeIPSecAH,
	layers.LayerTypeIPSecESP,
	layers.LayerTypeNTP,
	layers.LayerTypeSIP,
	layers.LayerTypeTLS,
}

func recoverPacket(pcapPacket gopacket.Packet) gopacket.Packet {
	if pcapPacket == nil || pcapPacket.ErrorLayer() == nil {
		return pcapPacket
	}

	data := pcapPacket.Data()
	if len(data) >= 20 {
		version := data[0] >> 4
		var fallback gopacket.Packet
		if version == 4 {
			fallback = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
		} else if version == 6 && len(data) >= 40 {
			fallback = gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default)
		} else if len(data) >= 16 {
			fallback = gopacket.NewPacket(data, layers.LayerTypeLinuxSLL, gopacket.Default)
		}

		if fallback != nil && (fallback.NetworkLayer() != nil || fallback.LinkLayer() != nil) && fallback.ErrorLayer() == nil {
			fallback.Metadata().CaptureInfo = pcapPacket.Metadata().CaptureInfo
			return fallback
		}
	}

	return pcapPacket
}

func getLinkType(packets []gopacket.Packet) layers.LinkType {
	if len(packets) == 0 {
		return layers.LinkTypeEthernet
	}

	first := packets[0]
	if first.LinkLayer() != nil {
		switch first.LinkLayer().(type) {
		case *layers.LinuxSLL:
			return layers.LinkTypeLinuxSLL
		case *layers.FDDI:
			return layers.LinkTypeFDDI
		case *layers.Ethernet:
			return layers.LinkTypeEthernet
		}
	}

	data := first.Data()
	if len(data) > 0 {
		version := data[0] >> 4
		if version == 4 {
			return layers.LinkTypeIPv4
		} else if version == 6 {
			return layers.LinkTypeIPv6
		}
	}

	return layers.LinkTypeEthernet
}

func ParsePcap(filename string, offset int, count int, unwrap bool, excludeErrors bool) ([]*model.Packet, bool, error) {
	packets := make([]*model.Packet, 0)
	matchingIndex := 0
	hasErrors := false
	err := parsePcapFile(filename, "", func(index int, pcapPacket gopacket.Packet) bool {
		pcapPacket = recoverPacket(pcapPacket)
		isError := pcapPacket.ErrorLayer() != nil
		if isError {
			hasErrors = true
		}
		if excludeErrors && isError {
			return true
		}
		if matchingIndex >= offset {
			packet := model.NewPacket(index)
			parseData(pcapPacket, packet, unwrap)
			packets = append(packets, packet)
		}
		matchingIndex++
		return len(packets) < count
	})
	return packets, hasErrors, err
}

func ToStream(packets []gopacket.Packet) (io.ReadCloser, int, error) {
	var snaplen uint32 = 65536
	var full bytes.Buffer

	writer := pcapgo.NewWriter(&full)
	writer.WriteFileHeader(snaplen, getLinkType(packets))

	for _, packet := range packets {
		err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		if err != nil {
			return nil, 0, err
		}
	}
	return io.NopCloser(bytes.NewReader(full.Bytes())), full.Len(), nil
}

func filterPacket(filter *model.Filter, packet gopacket.Packet) bool {
	timestamp := packet.Metadata().Timestamp
	if (!filter.BeginTime.IsZero() && filter.BeginTime.After(timestamp)) ||
		(!filter.EndTime.IsZero() && filter.EndTime.Before(timestamp)) {
		return false
	}

	return true
}

func ParseRawPcap(filename string, maxCount int, filter *model.Filter) ([]gopacket.Packet, error) {
	packets := make([]gopacket.Packet, 0)
	currentCount := 0
	err := parsePcapFile(filename, CreateBpf(filter, true), func(index int, pcapPacket gopacket.Packet) bool {
		if filterPacket(filter, pcapPacket) {
			packets = append(packets, pcapPacket)
			currentCount += 1
		}

		return currentCount < maxCount
	})

	if currentCount == maxCount {
		log.WithFields(log.Fields{
			"packetCount": len(packets),
		}).Warn("Exceeded packet capture limit for job; returned PCAP will be truncated")
	}

	return packets, err
}

func AddBpf(bpf string, part string) string {
	if len(part) == 0 {
		return bpf
	}

	newBpf := bpf

	if len(newBpf) > 0 {
		newBpf = newBpf + " and "
	}

	newBpf = newBpf + part

	return newBpf

}

func CreateBpf(filter *model.Filter, vlanEnabled bool) string {
	query := filter.Protocol
	if strings.HasPrefix(filter.Protocol, model.PROTOCOL_ICMP) {
		query = "(icmp or icmp6)"
	}

	if len(filter.SrcIp) > 0 {
		query = AddBpf(query, fmt.Sprintf("host %s", filter.SrcIp))
	}

	if len(filter.DstIp) > 0 {
		query = AddBpf(query, fmt.Sprintf("host %s", filter.DstIp))
	}

	// Some legacy jobs won't have the protocol provided
	if !strings.HasPrefix(filter.Protocol, model.PROTOCOL_ICMP) {
		if filter.SrcPort > 0 {
			query = AddBpf(query, fmt.Sprintf("port %d", filter.SrcPort))
		}

		if filter.DstPort > 0 {
			query = AddBpf(query, fmt.Sprintf("port %d", filter.DstPort))
		}
	}

	// Repeat the query but with vlan applied
	if vlanEnabled && len(query) > 0 {
		query = fmt.Sprintf("(%s) or (vlan and %s)", query, query)
	}

	return query
}

func UnwrapPcap(filename string, unwrappedFilename string) bool {
	unwrapped := false
	info, err := os.Stat(unwrappedFilename)
	if os.IsNotExist(err) {
		unwrappedFile, err := os.Create(unwrappedFilename)
		if err != nil {
			log.WithError(err).WithField("unwrappedFilename", unwrappedFilename).Error("Unable to create unwrapped file")
		} else {
			writer := pcapgo.NewWriter(unwrappedFile)
			err = writer.WriteFileHeader(65535, layers.LinkTypeEthernet)
			if err != nil {
				log.WithError(err).WithField("unwrappedFilename", unwrappedFilename).Error("Unable to write unwrapped file header")
			} else {
				defer unwrappedFile.Close()
				err = parsePcapFile(filename, "", func(index int, pcapPacket gopacket.Packet) bool {
					newPacket := unwrapVxlanPacket(pcapPacket, nil)
					err = writer.WritePacket(newPacket.Metadata().CaptureInfo, newPacket.Data())
					if err != nil {
						log.WithError(err).WithFields(log.Fields{
							"unwrappedFilename": unwrappedFilename,
							"index":             index,
						}).Error("Unable to write unwrapped file packet")
						return false
					}
					return true
				})
				if err != nil {
					log.WithError(err).WithField("filename", filename).Error("Unable to parse PCAP into unwrapped PCAP")
				} else {
					unwrapped = true
				}
			}
		}
	} else if info.IsDir() {
		log.WithField("unwrappedFilename", unwrappedFilename).Error("Unexpected directory found with unwrapped filename")
	} else {
		unwrapped = true
	}

	return unwrapped

}

func parsePcapFile(filename string, bpf string, handler func(int, gopacket.Packet) bool) (err error) {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{
				"pcap":  filename,
				"panic": r,
			}).Error("Recovered from PCAP decode panic")
			err = fmt.Errorf("packet decode panic: %v", r)
		}
	}()

	handle, err := pcap.OpenOffline(filename)
	if err == nil {
		defer handle.Close()
		if bpf != "" {
			err = handle.SetBPFFilter(bpf)
			if err != nil {
				log.WithError(err).WithField("pcapBpf", bpf).Error("Invalid BPF")
				return err
			}
		}
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		packetSource.DecodeOptions.Lazy = true
		packetSource.DecodeOptions.NoCopy = true
		packetSource.DecodeOptions.SkipDecodeRecovery = true
		index := 0
		for pcapPacket := range packetSource.Packets() {
			if pcapPacket != nil {
				if !handler(index, pcapPacket) {
					break
				}
				index++
			}
		}
	}
	return err
}

func overrideType(packet *model.Packet, layerType gopacket.LayerType) {
	if layerType != gopacket.LayerTypePayload {
		packet.Type = layerType.String()
	}
}

func unwrapVxlanPacket(pcapPacket gopacket.Packet, packet *model.Packet) gopacket.Packet {
	vxlan := pcapPacket.Layer(layers.LayerTypeVXLAN)
	if vxlan != nil {
		vxlan, _ := vxlan.(*layers.VXLAN)
		if vxlan.Payload != nil && len(vxlan.Payload) > 0 {
			oldData := pcapPacket.Metadata()
			pcapPacket = gopacket.NewPacket(vxlan.Payload, layers.LayerTypeEthernet, gopacket.Default)
			newData := pcapPacket.Metadata()
			newData.Timestamp = oldData.Timestamp
			newData.CaptureLength = len(vxlan.Payload)
			newData.Length = newData.CaptureLength
			if packet != nil {
				packet.Flags = append(packet.Flags, "VXLAN")
			}
		}
	}
	return pcapPacket
}

func parseData(pcapPacket gopacket.Packet, packet *model.Packet, unwrap bool) {
	defer func() {
		if r := recover(); r != nil {
			packet.Type = "DecodeFailure"
			packet.Error = fmt.Sprintf("Decode panic: %v", r)
		}
	}()

	if unwrap {
		pcapPacket = unwrapVxlanPacket(pcapPacket, packet)
	}
	pcapPacket = recoverPacket(pcapPacket)

	packet.Timestamp = pcapPacket.Metadata().Timestamp
	packet.Length = pcapPacket.Metadata().Length

	linkLayer := pcapPacket.LinkLayer()
	if linkLayer != nil {
		if eth, ok := linkLayer.(*layers.Ethernet); ok {
			packet.SrcMac = eth.SrcMAC.String()
			packet.DstMac = eth.DstMAC.String()
		}
	}

	if pcapPacket.Layer(layers.LayerTypeDot1Q) != nil {
		packet.Flags = append(packet.Flags, "VLAN")
	}

	netLayer := pcapPacket.NetworkLayer()
	if netLayer != nil {
		if ip6, ok := netLayer.(*layers.IPv6); ok {
			packet.SrcIp = ip6.SrcIP.String()
			packet.DstIp = ip6.DstIP.String()
		} else if ip4, ok := netLayer.(*layers.IPv4); ok {
			packet.SrcIp = ip4.SrcIP.String()
			packet.DstIp = ip4.DstIP.String()
		}
	}

	for _, layerType := range SupportedLayerTypes {
		layer := pcapPacket.Layer(layerType)
		if layer != nil {
			overrideType(packet, layer.LayerType())
		}
	}

	layer := pcapPacket.Layer(layers.LayerTypeTCP)
	if layer != nil {
		layer := layer.(*layers.TCP)
		packet.SrcPort = int(layer.SrcPort)
		packet.DstPort = int(layer.DstPort)
		packet.Sequence = int(layer.Seq)
		packet.Acknowledge = int(layer.Ack)
		packet.Window = int(layer.Window)
		packet.Checksum = int(layer.Checksum)
		if layer.SYN {
			packet.Flags = append(packet.Flags, "SYN")
		}
		if layer.PSH {
			packet.Flags = append(packet.Flags, "PSH")
		}
		if layer.FIN {
			packet.Flags = append(packet.Flags, "FIN")
		}
		if layer.RST {
			packet.Flags = append(packet.Flags, "RST")
		}
		if layer.ACK {
			packet.Flags = append(packet.Flags, "ACK")
		}
		overrideType(packet, layer.SrcPort.LayerType())
		overrideType(packet, layer.DstPort.LayerType())
		overrideType(packet, layer.LayerType())
	}

	layer = pcapPacket.Layer(layers.LayerTypeUDP)
	if layer != nil {
		layer := layer.(*layers.UDP)
		packet.SrcPort = int(layer.SrcPort)
		packet.DstPort = int(layer.DstPort)
		packet.Checksum = int(layer.Checksum)
		overrideType(packet, layer.NextLayerType())
		overrideType(packet, layer.LayerType())
	}

	packetLayers := pcapPacket.Layers()
	if len(packetLayers) > 0 {
		topLayer := packetLayers[len(packetLayers)-1]
		overrideType(packet, topLayer.LayerType())
	}

	if errLayer := pcapPacket.ErrorLayer(); errLayer != nil {
		packet.Error = errLayer.Error().Error()
	}

	packet.Payload = base64.StdEncoding.EncodeToString(pcapPacket.Data())
	packet.PayloadOffset = 0
	appLayer := pcapPacket.ApplicationLayer()
	if appLayer != nil {
		packet.PayloadOffset = len(pcapPacket.Data()) - len(appLayer.Payload())
	}
}
