<script setup lang="ts">
// Copyright 2020-2025 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

import { computed, ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import L from 'leaflet'
import type { MapWidgetData, MapConnection, MapMarker, GeoPoint } from '../../../types/dashboard'

const props = defineProps<{
    data: MapWidgetData
}>()

const mapContainer = ref<HTMLDivElement | null>(null)
const wrapperRef = ref<HTMLDivElement | null>(null)
let map: L.Map | null = null
let animationLayers: L.LayerGroup | null = null
let markersLayer: L.LayerGroup | null = null
const animationTimers = ref<number[]>([])
const mapReady = ref(false)
let resizeObserver: ResizeObserver | null = null

// Determine map mode
const mapMode = computed(() => props.data.mapMode || 'connections')
const isAlertMode = computed(() => mapMode.value === 'alerts')

// Geographic coordinates for named locations (legacy support)
const locationCoords: Record<string, { lat: number; lng: number; label: string }> = {
    'us-east': { lat: 40.7128, lng: -74.0060, label: 'US East' },
    'us-west': { lat: 37.7749, lng: -122.4194, label: 'US West' },
    'us-central': { lat: 41.8781, lng: -87.6298, label: 'US Central' },
    'canada': { lat: 45.4215, lng: -75.6972, label: 'Canada' },
    'mexico': { lat: 19.4326, lng: -99.1332, label: 'Mexico' },
    'brazil': { lat: -23.5505, lng: -46.6333, label: 'Brazil' },
    'argentina': { lat: -34.6037, lng: -58.3816, label: 'Argentina' },
    'uk': { lat: 51.5074, lng: -0.1278, label: 'UK' },
    'germany': { lat: 52.5200, lng: 13.4050, label: 'Germany' },
    'france': { lat: 48.8566, lng: 2.3522, label: 'France' },
    'netherlands': { lat: 52.3676, lng: 4.9041, label: 'Netherlands' },
    'russia-west': { lat: 55.7558, lng: 37.6173, label: 'Russia' },
    'russia-east': { lat: 56.0153, lng: 92.8932, label: 'Russia East' },
    'china': { lat: 39.9042, lng: 116.4074, label: 'China' },
    'japan': { lat: 35.6762, lng: 139.6503, label: 'Japan' },
    'korea': { lat: 37.5665, lng: 126.9780, label: 'Korea' },
    'north-korea': { lat: 39.0392, lng: 125.7625, label: 'North Korea' },
    'india': { lat: 28.6139, lng: 77.2090, label: 'India' },
    'singapore': { lat: 1.3521, lng: 103.8198, label: 'Singapore' },
    'iran': { lat: 35.6892, lng: 51.3890, label: 'Iran' },
    'israel': { lat: 31.7683, lng: 35.2137, label: 'Israel' },
    'uae': { lat: 25.2048, lng: 55.2708, label: 'UAE' },
    'south-africa': { lat: -33.9249, lng: 18.4241, label: 'South Africa' },
    'nigeria': { lat: 6.5244, lng: 3.3792, label: 'Nigeria' },
    'egypt': { lat: 30.0444, lng: 31.2357, label: 'Egypt' },
    'australia': { lat: -33.8688, lng: 151.2093, label: 'Australia' },
    'local': { lat: 39.8283, lng: -98.5795, label: 'Local Network' }
}

// Get color based on type
const getTypeColor = (type?: string): string => {
    switch (type) {
        case 'attack': return '#ef4444'
        case 'blocked': return '#eab308'
        case 'allowed': return '#22c55e'
        case 'scan': return '#a855f7'
        case 'alert': return '#ef4444'
        default: return '#3b82f6'
    }
}

// Get coordinates from a location (supports both string keys and GeoPoint)
const getCoords = (location: string | GeoPoint): { lat: number; lng: number; label: string } => {
    if (typeof location === 'string') {
        return locationCoords[location] || { lat: 0, lng: 0, label: location }
    }
    return {
        lat: location.lat,
        lng: location.lng,
        label: location.label || location.country || 'Unknown'
    }
}

// Create curved path points between two locations
const createArcPoints = (from: L.LatLng, to: L.LatLng, numPoints: number = 50): L.LatLng[] => {
    const points: L.LatLng[] = []

    const midLat = (from.lat + to.lat) / 2
    const midLng = (from.lng + to.lng) / 2
    const distance = from.distanceTo(to)
    const arcHeight = Math.min(distance / 100000, 20)

    for (let i = 0; i <= numPoints; i++) {
        const t = i / numPoints
        const lat = from.lat + (to.lat - from.lat) * t
        const lng = from.lng + (to.lng - from.lng) * t
        const arcOffset = Math.sin(t * Math.PI) * arcHeight
        points.push(L.latLng(lat + arcOffset, lng))
    }

    return points
}

// Animate a single connection
const animateConnection = (conn: MapConnection, index: number) => {
    if (!map || !animationLayers) return

    const from = getCoords(conn.from)
    const to = getCoords(conn.to)
    const color = conn.color || getTypeColor(conn.type)

    const fromLatLng = L.latLng(from.lat, from.lng)
    const toLatLng = L.latLng(to.lat, to.lng)

    const arcPoints = createArcPoints(fromLatLng, toLatLng)

    let currentSegment = 0
    const segmentLength = 10

    const animateLine = () => {
        if (!animationLayers) return

        animationLayers.eachLayer((layer: any) => {
            if (layer.options?.connectionIndex === index && layer.options?.isAnimation) {
                animationLayers?.removeLayer(layer)
            }
        })

        const startIdx = currentSegment
        const endIdx = Math.min(currentSegment + segmentLength, arcPoints.length - 1)

        if (startIdx < arcPoints.length - 1) {
            const segmentPoints = arcPoints.slice(startIdx, endIdx + 1)

            const animatedLine = L.polyline(segmentPoints, {
                color: color,
                weight: 3,
                opacity: 0.9,
                className: 'pew-line',
                // @ts-ignore
                connectionIndex: index,
                isAnimation: true
            })
            animationLayers.addLayer(animatedLine)

            if (segmentPoints.length > 0) {
                const headPoint = segmentPoints[segmentPoints.length - 1]
                const headMarker = L.circleMarker(headPoint, {
                    radius: 4,
                    color: color,
                    fillColor: '#ffffff',
                    fillOpacity: 1,
                    weight: 2,
                    // @ts-ignore
                    connectionIndex: index,
                    isAnimation: true
                })
                animationLayers.addLayer(headMarker)
            }

            currentSegment += 3

            if (currentSegment < arcPoints.length) {
                requestAnimationFrame(animateLine)
            } else {
                createImpactBurst(toLatLng, color, index)
            }
        }
    }

    animateLine()
}

// Create impact burst effect
const createImpactBurst = (latLng: L.LatLng, color: string, index: number) => {
    if (!animationLayers) return

    let radius = 5
    const maxRadius = 20

    const burst = L.circleMarker(latLng, {
        radius: radius,
        color: color,
        fillColor: color,
        fillOpacity: 0.6,
        weight: 2,
        // @ts-ignore
        connectionIndex: index,
        isAnimation: true
    })
    animationLayers.addLayer(burst)

    const expandBurst = () => {
        radius += 2
        burst.setRadius(radius)
        burst.setStyle({ fillOpacity: 0.6 * (1 - radius / maxRadius), opacity: 1 - radius / maxRadius })

        if (radius < maxRadius) {
            requestAnimationFrame(expandBurst)
        } else {
            animationLayers?.removeLayer(burst)
        }
    }

    expandBurst()
}

// Stats computation
const stats = computed(() => {
    if (isAlertMode.value && props.data.markers) {
        const total = props.data.markers.reduce((sum, m) => sum + m.count, 0)
        return { total, alerts: total }
    }
    if (props.data.connections) {
        const byType: Record<string, number> = {}
        props.data.connections.forEach(conn => {
            const type = conn.type || 'unknown'
            byType[type] = (byType[type] || 0) + conn.count
        })
        return byType
    }
    return {}
})

const totalCount = computed(() => {
    if (isAlertMode.value && props.data.markers) {
        return props.data.markers.reduce((sum, m) => sum + m.count, 0)
    }
    if (props.data.connections) {
        return props.data.connections.reduce((sum, c) => sum + c.count, 0)
    }
    return 0
})

// Check if we have data
const hasData = computed(() => {
    if (isAlertMode.value) {
        return props.data.markers && props.data.markers.length > 0
    }
    return props.data.connections && props.data.connections.length > 0
})

// Render alert markers
const renderAlertMarkers = () => {
    if (!map || !markersLayer || !props.data.markers) return

    markersLayer.clearLayers()

    const markers = props.data.markers
    const maxCount = Math.max(...markers.map(m => m.count), 1)

    markers.forEach(marker => {
        const coords = marker.location
        if (coords.lat === 0 && coords.lng === 0) return

        // Scale radius based on count (min 8, max 30)
        const ratio = marker.count / maxCount
        const radius = 8 + ratio * 22

        const color = marker.color || getTypeColor(marker.type)

        // Outer glow circle
        const glowMarker = L.circleMarker([coords.lat, coords.lng], {
            radius: radius + 4,
            color: color,
            fillColor: color,
            fillOpacity: 0.2,
            weight: 0,
            className: 'alert-marker-glow'
        })
        markersLayer.addLayer(glowMarker)

        // Main marker
        const circleMarker = L.circleMarker([coords.lat, coords.lng], {
            radius: radius,
            color: color,
            fillColor: color,
            fillOpacity: 0.6,
            weight: 2,
            className: 'alert-marker'
        })

        const label = coords.label || coords.country || 'Unknown'
        circleMarker.bindTooltip(
            `<strong>${label}</strong><br/>${marker.count.toLocaleString()} alerts`,
            { direction: 'top' }
        )

        markersLayer.addLayer(circleMarker)
    })
}

// Render connection mode
const renderConnections = () => {
    if (!map || !animationLayers || !props.data.connections) return

    // Add location markers
    const targetLocations = new Set<string>()
    const geoLocations: GeoPoint[] = []

    props.data.connections.forEach(conn => {
        if (typeof conn.from === 'string') {
            targetLocations.add(conn.from)
        } else {
            geoLocations.push(conn.from)
        }
        if (typeof conn.to === 'string') {
            targetLocations.add(conn.to)
        } else {
            geoLocations.push(conn.to)
        }
    })

    // Add named location markers
    targetLocations.forEach(loc => {
        const coords = getCoords(loc)
        if (coords.lat === 0 && coords.lng === 0) return

        const marker = L.circleMarker([coords.lat, coords.lng], {
            radius: 6,
            color: '#3b82f6',
            fillColor: '#3b82f6',
            fillOpacity: 0.8,
            weight: 2,
            className: 'location-marker'
        })
        marker.bindTooltip(coords.label, { permanent: false, direction: 'top' })
        marker.addTo(map!)
    })

    // Add geo point markers
    geoLocations.forEach(geo => {
        if (geo.lat === 0 && geo.lng === 0) return

        const marker = L.circleMarker([geo.lat, geo.lng], {
            radius: 6,
            color: '#3b82f6',
            fillColor: '#3b82f6',
            fillOpacity: 0.8,
            weight: 2,
            className: 'location-marker'
        })
        marker.bindTooltip(geo.label || geo.country || 'Unknown', { permanent: false, direction: 'top' })
        marker.addTo(map!)
    })

    // Draw base connection lines
    props.data.connections.forEach(conn => {
        const from = getCoords(conn.from)
        const to = getCoords(conn.to)
        if ((from.lat === 0 && from.lng === 0) || (to.lat === 0 && to.lng === 0)) return

        const color = conn.color || getTypeColor(conn.type)

        const fromLatLng = L.latLng(from.lat, from.lng)
        const toLatLng = L.latLng(to.lat, to.lng)

        const arcPoints = createArcPoints(fromLatLng, toLatLng)

        L.polyline(arcPoints, {
            color: color,
            weight: 1,
            opacity: 0.2,
            dashArray: '5, 10'
        }).addTo(map!)
    })

    // Start animations
    props.data.connections.forEach((conn, idx) => {
        const from = getCoords(conn.from)
        const to = getCoords(conn.to)
        if ((from.lat === 0 && from.lng === 0) || (to.lat === 0 && to.lng === 0)) return

        const delay = Math.random() * 2000
        const interval = 3000 + Math.random() * 2000

        setTimeout(() => animateConnection(conn, idx), delay)

        const timer = window.setInterval(() => animateConnection(conn, idx), interval)
        animationTimers.value.push(timer)
    })
}

// Initialize map
const initMap = () => {
    if (!mapContainer.value) return

    const bounds = L.latLngBounds(
        L.latLng(-85, -180),
        L.latLng(85, 180)
    )

    map = L.map(mapContainer.value, {
        center: [20, 0],
        zoom: 2,
        minZoom: 1,
        maxZoom: 8,
        zoomControl: false,
        attributionControl: false,
        maxBounds: bounds,
        maxBoundsViscosity: 1.0,
        worldCopyJump: false
    })

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        subdomains: 'abcd',
        maxZoom: 19,
        noWrap: true
    }).addTo(map)

    L.control.zoom({ position: 'topright' }).addTo(map)

    animationLayers = L.layerGroup().addTo(map)
    markersLayer = L.layerGroup().addTo(map)

    if (isAlertMode.value) {
        renderAlertMarkers()
    } else {
        renderConnections()
    }
}

// Setup resize observer
const setupResizeObserver = () => {
    if (!wrapperRef.value) return

    resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
            const { width, height } = entry.contentRect
            if (width > 0 && height > 0 && !mapReady.value) {
                mapReady.value = true
                nextTick(() => initMap())
            } else if (map && width > 0 && height > 0) {
                map.invalidateSize()
            }
        }
    })

    resizeObserver.observe(wrapperRef.value)
}

onMounted(() => {
    nextTick(() => {
        setupResizeObserver()
        setTimeout(() => {
            if (!mapReady.value && mapContainer.value) {
                const rect = mapContainer.value.getBoundingClientRect()
                if (rect.width > 0 && rect.height > 0) {
                    mapReady.value = true
                    initMap()
                }
            }
        }, 100)
    })
})

onUnmounted(() => {
    animationTimers.value.forEach(timer => clearInterval(timer))
    animationTimers.value = []

    if (resizeObserver) {
        resizeObserver.disconnect()
        resizeObserver = null
    }

    if (map) {
        map.remove()
        map = null
    }
})

// Watch for data changes
watch(() => props.data, () => {
    if (map && markersLayer) {
        if (isAlertMode.value) {
            renderAlertMarkers()
        }
    }
}, { deep: true })
</script>

<template>
    <div ref="wrapperRef" class="map-wrapper">
        <div ref="mapContainer" class="map-container"></div>

        <!-- Loading indicator -->
        <div v-if="!mapReady" class="absolute inset-0 flex items-center justify-center text-gray-400">
            <div class="text-center">
                <div class="animate-pulse">Loading map...</div>
            </div>
        </div>

        <!-- No data message -->
        <div v-else-if="!hasData" class="absolute inset-0 flex items-center justify-center text-gray-400 bg-black/50">
            <div class="text-center">
                <div>No geographic data available</div>
            </div>
        </div>

        <!-- Stats overlay -->
        <div class="absolute bottom-2 left-2 right-2 flex gap-3 text-xs z-[1000]">
            <div class="bg-black/70 rounded px-2 py-1 text-white">
                <span class="text-gray-400">Total:</span>
                <span class="font-bold ml-1">{{ totalCount.toLocaleString() }}</span>
            </div>
            <template v-if="!isAlertMode">
                <div v-if="stats.attack" class="bg-black/70 rounded px-2 py-1 flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-red-500"></span>
                    <span class="text-red-400">{{ stats.attack?.toLocaleString() }}</span>
                </div>
                <div v-if="stats.blocked" class="bg-black/70 rounded px-2 py-1 flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-yellow-500"></span>
                    <span class="text-yellow-400">{{ stats.blocked?.toLocaleString() }}</span>
                </div>
                <div v-if="stats.scan" class="bg-black/70 rounded px-2 py-1 flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-purple-500"></span>
                    <span class="text-purple-400">{{ stats.scan?.toLocaleString() }}</span>
                </div>
            </template>
        </div>

        <!-- Legend -->
        <div v-if="data.showLegend !== false" class="absolute top-2 left-2 bg-black/70 rounded px-2 py-1 text-[10px] text-white space-y-0.5 z-[1000]">
            <template v-if="isAlertMode">
                <div class="flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-red-500"></span>
                    <span>Alerts</span>
                </div>
                <div class="text-gray-400 text-[9px]">Size = count</div>
            </template>
            <template v-else>
                <div class="flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-red-500"></span>
                    <span>Attacks</span>
                </div>
                <div class="flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-yellow-500"></span>
                    <span>Blocked</span>
                </div>
                <div class="flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-purple-500"></span>
                    <span>Scans</span>
                </div>
                <div class="flex items-center gap-1">
                    <span class="w-2 h-2 rounded-full bg-green-500"></span>
                    <span>Allowed</span>
                </div>
            </template>
        </div>

        <!-- Attribution -->
        <div class="absolute bottom-2 right-2 text-[9px] text-gray-500 z-[1000]">
            © <a href="https://www.openstreetmap.org/copyright" target="_blank" class="hover:text-gray-400">OpenStreetMap</a>
            © <a href="https://carto.com/attributions" target="_blank" class="hover:text-gray-400">CARTO</a>
        </div>
    </div>
</template>

<style scoped>
.map-wrapper {
    width: 100%;
    height: 280px;
    position: relative;
    background: #1a1a2e;
}

.map-container {
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    border-radius: 0.25rem;
    overflow: hidden;
}

:deep(.leaflet-container) {
    background: #1a1a2e;
    width: 100% !important;
    height: 100% !important;
}

:deep(.leaflet-tile-pane) {
    opacity: 1;
}

:deep(.location-marker) {
    animation: pulse 2s ease-in-out infinite;
}

:deep(.alert-marker) {
    animation: alertPulse 3s ease-in-out infinite;
}

:deep(.alert-marker-glow) {
    animation: glowPulse 2s ease-in-out infinite;
}

@keyframes pulse {
    0%, 100% {
        opacity: 0.8;
    }
    50% {
        opacity: 1;
    }
}

@keyframes alertPulse {
    0%, 100% {
        opacity: 0.6;
        transform: scale(1);
    }
    50% {
        opacity: 0.8;
        transform: scale(1.05);
    }
}

@keyframes glowPulse {
    0%, 100% {
        opacity: 0.2;
    }
    50% {
        opacity: 0.4;
    }
}

:deep(.pew-line) {
    filter: drop-shadow(0 0 3px currentColor);
}
</style>
