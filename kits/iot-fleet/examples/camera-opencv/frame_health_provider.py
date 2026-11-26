"""Optional agent-editable OpenCV camera frame-health provider starter.

NOTE FOR AGENTS AND ENGINEERS:
This file is NOT installed by default when you run `cruxible kit add iot-fleet`, so non-camera
fleets do not pull a ~50 MB native OpenCV wheel. It is a starting template meant for your agent
to customize for your camera pipeline (blur threshold, dark/occluded lens luma, frozen-frame
pixel diff, ROI masks, or RTSP snapshot metadata) and publish directly to your Cruxible
instance with `cruxible provider publish`:

    # Example once adapted to your camera snapshot schema:
    cruxible provider publish examples/camera-opencv/frame_health_provider.py

Dependencies if you publish this provider:
    cruxible-provider-runtime>=0.6.0
    opencv-python-headless>=4.10
    numpy>=1.26
"""

from __future__ import annotations

import json
from typing import Any

import cv2
import numpy as np
from cruxible_provider_runtime import CaptureView, decline, derive
from cruxible_provider_runtime.provider_api import ProviderResult


def check_frame_bytes(
    current_jpeg: bytes,
    previous_jpeg: bytes | None = None,
    *,
    blur_laplacian_min: float = 80.0,
    dark_luma_min: float = 18.0,
    frozen_mad_max: float = 0.5,
) -> dict[str, Any]:
    """Classify one camera frame (JPEG/PNG bytes) for blur, lens occlusion, or frozen stream."""

    buf = np.frombuffer(current_jpeg, dtype=np.uint8)
    gray = cv2.imdecode(buf, cv2.IMREAD_GRAYSCALE)
    if gray is None:
        raise ValueError("current frame bytes could not be decoded as an image")

    mean_luma = float(np.mean(gray))
    laplacian_var = float(cv2.Laplacian(gray, cv2.CV_64F).var())
    mad: float | None = None
    if previous_jpeg is not None:
        prev_buf = np.frombuffer(previous_jpeg, dtype=np.uint8)
        prev_gray = cv2.imdecode(prev_buf, cv2.IMREAD_GRAYSCALE)
        if prev_gray is not None and prev_gray.shape == gray.shape:
            mad = float(np.mean(np.abs(gray.astype(np.float32) - prev_gray.astype(np.float32))))

    issues: list[str] = []
    if mean_luma < dark_luma_min:
        issues.append("lens_occluded_or_dark")
    if laplacian_var < blur_laplacian_min:
        issues.append("out_of_focus_or_dirty_lens")
    if mad is not None and mad <= frozen_mad_max:
        issues.append("frozen_stream")

    status = "degraded" if issues else "online"
    return {
        "status": status,
        "issues": issues,
        "mean_luma": round(mean_luma, 2),
        "laplacian_var": round(laplacian_var, 2),
        "frame_diff_mad": round(mad, 3) if mad is not None else None,
    }


@derive(
    "camera.frame_health",
    serves="fleet.camera.frame_health",
    input_contract="fleet.camera.frame_health.request@1",
    output_contract="fleet.camera.frame_health.result@1",
    refusals={
        "provider_declined": {
            "contract": "camera.frame_health.refusal.provider_declined@1",
            "absorbable": False,
        }
    },
)
def camera_frame_health(
    current_frame: CaptureView,
    previous_frame: CaptureView | None = None,
    logical_source: str = "fleet.camera.frame",
) -> ProviderResult:
    """Pure @derive OpenCV check: blur, lens occlusion, and frozen-frame detection."""

    try:
        report = check_frame_bytes(
            current_frame.raw_bytes,
            previous_frame.raw_bytes if previous_frame is not None else None,
        )
    except ValueError as exc:
        raise decline("provider_declined", str(exc)) from None

    content = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    return ProviderResult.ok(
        {
            "document": current_frame.derive(
                content,
                source_identity=logical_source,
                coordinate_type="http-response-v1",
                coordinate={"status": report["status"]},
                selector_type="whole-response-v1",
            )
        }
    )
