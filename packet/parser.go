// Copyright Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package packet

import (
  "encoding/base64"
  "github.com/apex/log"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "github.com/google/gopacket/pcapgo"
  "github.com/security-onion-solutions/securityonion-soc/model"
  "os"
)

var SupportedLayerTypes = [...]gopacket.LayerType{
  layers.LayerTypeARP,
  layers.LayerTypeICMPv4,
  layers.LayerTypeICMPv6,
  layers.LayerTypeIPSecAH,
  layers.LayerTypeIPSecESP,
  layers.LayerTypeNTP,
  layers.LayerTypeSIP,
  layers.LayerTypeTLS,
}

func ParsePcap(filename string, offset int, count int, unwrap bool) ([]*model.Packet, error) {
  packets := make([]*model.Packet, 0)
  parsePcapFile(filename, func(index int, pcapPacket gopacket.Packet) bool {
    if index >= offset {
      packet := model.NewPacket(index)
      parseData(pcapPacket, packet, unwrap)
      packets = append(packets, packet)
    }
    return len(packets) < count
  })
  return packets, nil
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
        err = parsePcapFile(filename, func(index int, pcapPacket gopacket.Packet) bool {
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

func parsePcapFile(filename string, handler func(int, gopacket.Packet) bool) error {
  handle, err := pcap.OpenOffline(filename)
  if err == nil {
    defer handle.Close()
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.DecodeOptions.Lazy = true
    packetSource.DecodeOptions.NoCopy = true
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
  if unwrap {
    pcapPacket = unwrapVxlanPacket(pcapPacket, packet)
  }

  packet.Timestamp = pcapPacket.Metadata().Timestamp
  packet.Length = pcapPacket.Metadata().Length

  layer := pcapPacket.Layer(layers.LayerTypeEthernet)
  if layer != nil {
    layer := layer.(*layers.Ethernet)
    packet.SrcMac = layer.SrcMAC.String()
    packet.DstMac = layer.DstMAC.String()
  }

  layer = pcapPacket.Layer(layers.LayerTypeIPv6)
  if layer != nil {
    layer := layer.(*layers.IPv6)
    packet.SrcIp = layer.SrcIP.String()
    packet.DstIp = layer.DstIP.String()
  } else {
    layer = pcapPacket.Layer(layers.LayerTypeIPv4)
    if layer != nil {
      layer := layer.(*layers.IPv4)
      packet.SrcIp = layer.SrcIP.String()
      packet.DstIp = layer.DstIP.String()
    }
  }

  for _, layerType := range SupportedLayerTypes {
    layer = pcapPacket.Layer(layerType)
    if layer != nil {
      overrideType(packet, layer.LayerType())
    }
  }

  layer = pcapPacket.Layer(layers.LayerTypeTCP)
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
  topLayer := packetLayers[len(packetLayers)-1]
  overrideType(packet, topLayer.LayerType())

  packet.Payload = base64.StdEncoding.EncodeToString(pcapPacket.Data())
  packet.PayloadOffset = 0
  appLayer := pcapPacket.ApplicationLayer()
  if appLayer != nil {
    packet.PayloadOffset = len(pcapPacket.Data()) - len(appLayer.Payload())
  }
}
