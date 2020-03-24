// Copyright 2019 Jason Ertel (jertel). All rights reserved.
//
// This program is distributed under the terms of version 2 of the
// GNU General Public License.  See LICENSE for further details.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

package packet

import (
  "encoding/base64"
  "github.com/google/gopacket"
  "github.com/google/gopacket/layers"
  "github.com/google/gopacket/pcap"
  "github.com/sensoroni/sensoroni/model"
)

var SupportedLayerTypes = [...]gopacket.LayerType {
  layers.LayerTypeARP,
  layers.LayerTypeICMPv4,
  layers.LayerTypeICMPv6,
  layers.LayerTypeIPSecAH,
  layers.LayerTypeIPSecESP,
  layers.LayerTypeNTP,
  layers.LayerTypeSIP,
  layers.LayerTypeTLS,
}

func ParsePcap(filename string, offset int, count int) ([]*model.Packet, error) {
  packets := make([]*model.Packet, 0)
  handle, err := pcap.OpenOffline(filename)
  if err == nil {
    defer handle.Close()
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    packetSource.DecodeOptions.Lazy = true
    packetSource.DecodeOptions.NoCopy = true
    index := 0
    for pcapPacket := range packetSource.Packets() {
      if pcapPacket != nil {
        index++
        if index >= offset {
          packet := model.NewPacket(index)
          packet.Timestamp = pcapPacket.Metadata().Timestamp
          packet.Length = pcapPacket.Metadata().Length
          parseData(pcapPacket, packet)
          packets = append(packets, packet)
          if len(packets) >= count {
            break
          }
        }
      }
    }
  }
  return packets, err
}

func overrideType(packet *model.Packet, layerType gopacket.LayerType) {
  if layerType != gopacket.LayerTypePayload {
    packet.Type = layerType.String()
  }
}

func parseData(pcapPacket gopacket.Packet, packet *model.Packet) {
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

  packetLayers := pcapPacket.Layers();
  topLayer := packetLayers[len(packetLayers)-1]
  overrideType(packet, topLayer.LayerType())
  
  packet.Payload = base64.StdEncoding.EncodeToString(pcapPacket.Data())
  packet.PayloadOffset = 0;
  appLayer := pcapPacket.ApplicationLayer();
  if appLayer != nil {
    packet.PayloadOffset = len(pcapPacket.Data()) - len(appLayer.Payload())
  }
}