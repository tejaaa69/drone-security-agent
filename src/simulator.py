"""
simulator.py

Generates a structured 24-hour simulation of drone telemetry and video frame
descriptions. Designed to produce a realistic security narrative with events
that exercise every rule in the alert engine.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class TelemetryFrame:
    timestamp: str          # "HH:MM"
    location: str           # Named zone on property
    altitude_m: float
    drone_speed_kmh: float
    battery_pct: int
    frame_description: str  # Natural-language description of what the camera sees
    frame_id: int = 0


# 24-hour scenario designed to test every alert rule
SIMULATION_SCENARIO: List[dict] = [
    # Morning quiet period
    {
        "timestamp": "00:01",
        "location": "Main Gate",
        "altitude_m": 15.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 98,
        "frame_description": (
            "Frame 1: A person in dark clothing is standing near the main gate, "
            "not moving for several minutes. No vehicle present. Poor lighting."
        ),
    },
    {
        "timestamp": "00:08",
        "location": "Main Gate",
        "altitude_m": 14.5,
        "drone_speed_kmh": 2.1,
        "battery_pct": 97,
        "frame_description": (
            "Frame 2: Same individual still loitering at main gate. They appear "
            "to be looking at their phone intermittently. No badge or uniform visible."
        ),
    },
    {
        "timestamp": "02:30",
        "location": "Perimeter Fence - NE Corner",
        "altitude_m": 18.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 91,
        "frame_description": (
            "Frame 3: Unidentified individual climbing over the perimeter fence "
            "at the northeast corner. Dark clothing. No visible ID or equipment."
        ),
    },
    # Early morning delivery
    {
        "timestamp": "06:45",
        "location": "Service Entrance",
        "altitude_m": 12.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 78,
        "frame_description": (
            "Frame 4: A white Ford Transit delivery van with 'Metro Logistics' "
            "branding has arrived at the service entrance. Driver in uniform is "
            "unloading boxes onto a trolley."
        ),
    },
    {
        "timestamp": "07:15",
        "location": "Service Entrance",
        "altitude_m": 12.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 74,
        "frame_description": (
            "Frame 5: White Ford Transit van departing service entrance. "
            "Delivery completed. Gate closing behind vehicle."
        ),
    },
    # Routine daytime activity
    {
        "timestamp": "08:30",
        "location": "Main Gate",
        "altitude_m": 15.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 65,
        "frame_description": (
            "Frame 6: Employee parking rush. Multiple vehicles entering. "
            "Sedan (grey Honda Civic) and a blue Ford F150 pickup truck both "
            "entering through main gate. Normal commuter activity."
        ),
    },
    {
        "timestamp": "09:15",
        "location": "North Parking Lot",
        "altitude_m": 20.0,
        "drone_speed_kmh": 3.5,
        "battery_pct": 60,
        "frame_description": (
            "Frame 7: Blue Ford F150 pickup truck parked in north lot, space B-12. "
            "Driver has exited and entered building. No unusual activity."
        ),
    },
    {
        "timestamp": "12:00",
        "location": "North Garage",
        "altitude_m": 14.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 52,
        "frame_description": (
            "Frame 8: Blue Ford F150 pickup truck parked near garage door, "
            "engine running. Driver is looking around repeatedly. "
            "Truck has been stationary for approximately 8 minutes."
        ),
    },
    {
        "timestamp": "12:47",
        "location": "Main Gate",
        "altitude_m": 15.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 48,
        "frame_description": (
            "Frame 9: Blue Ford F150 pickup truck exiting through main gate. "
            "Driver alone in vehicle."
        ),
    },
    # Afternoon normal activity
    {
        "timestamp": "14:20",
        "location": "East Courtyard",
        "altitude_m": 16.0,
        "drone_speed_kmh": 1.8,
        "battery_pct": 40,
        "frame_description": (
            "Frame 10: Three employees eating lunch in courtyard. "
            "Normal break activity. All wearing company lanyards."
        ),
    },
    # F150 returns — triggers repeat-vehicle rule
    {
        "timestamp": "17:30",
        "location": "Main Gate",
        "altitude_m": 15.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 30,
        "frame_description": (
            "Frame 11: Blue Ford F150 pickup truck re-entering property through "
            "main gate. This appears to be the same truck seen earlier today "
            "based on color and body style."
        ),
    },
    {
        "timestamp": "19:30",
        "location": "North Garage",
        "altitude_m": 14.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 22,
        "frame_description": (
            "Frame 12: Blue Ford F150 parked again near garage. Driver has "
            "exited and is standing by the door, appearing to wait for someone. "
            "Third observation of this vehicle today."
        ),
    },
    # Evening suspicious activity
    {
        "timestamp": "22:10",
        "location": "Loading Dock",
        "altitude_m": 12.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 88,  # battery swapped
        "frame_description": (
            "Frame 13: Two individuals at loading dock after business hours. "
            "One is attempting to access a keypad. No visible ID badges. "
            "A dark-colored SUV is parked nearby with engine running."
        ),
    },
    # Late night near perimeter
    {
        "timestamp": "23:58",
        "location": "Perimeter Fence - NE Corner",
        "altitude_m": 18.0,
        "drone_speed_kmh": 0.0,
        "battery_pct": 81,
        "frame_description": (
            "Frame 14: Unidentified person crouching near perimeter fence, "
            "northeast corner. Individual has been at this location for "
            "approximately 4 minutes. No vehicle visible."
        ),
    },
]

def get_simulation_frames() -> List[TelemetryFrame]:
    """Return all simulation frames as typed dataclass instances."""
    frames = []
    for i, raw in enumerate(SIMULATION_SCENARIO, start=1):
        frames.append(
            TelemetryFrame(
                frame_id=i,
                timestamp=raw["timestamp"],
                location=raw["location"],
                altitude_m=raw["altitude_m"],
                drone_speed_kmh=raw["drone_speed_kmh"],
                battery_pct=raw["battery_pct"],
                frame_description=raw["frame_description"],
            )
        )
    return frames


if __name__ == "__main__":
    for f in get_simulation_frames():
        print(f"[{f.timestamp}] {f.location} — {f.frame_description[:80]}...")