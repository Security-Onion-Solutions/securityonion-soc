#\!/bin/bash
# Test sigma conversion with a sample query

QUERY='aggregation: false
logsource:
  category: network
  service: connection
detection:
  selection:
    community_id: '"'"'1:vd6XDkuHdaufr8MOBuAP5Fjm5v8='"'"'
  condition: selection
fields:
  - src_ip
  - dst_ip
  - dst_port'

echo "$QUERY" | sigma convert -t security_onion -p /opt/sensoroni/sigma_final_pipeline.yaml -p /opt/sensoroni/sigma_so_pipeline.yaml -p windows-logsources -p ecs_windows --disable-pipeline-check /dev/stdin
