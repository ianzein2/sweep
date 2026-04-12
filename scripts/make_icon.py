#!/usr/bin/env python3
"""Generate the Sweep app icon — a stylized broom on a gradient background."""

from PIL import Image, ImageDraw
import subprocess
import os
import math

SIZE = 1024
PAD = int(SIZE * 0.08)  # padding inside rounded rect

def rounded_rect_mask(size, radius):
    """Create a rounded rectangle mask."""
    mask = Image.new("L", (size, size), 0)
    draw = ImageDraw.Draw(mask)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=255)
    return mask

def draw_icon():
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background: rounded rect with gradient (dark blue to teal)
    r = int(SIZE * 0.22)  # corner radius (macOS style)

    # Create gradient background
    for y in range(SIZE):
        t = y / SIZE
        # Dark navy to teal gradient
        cr = int(20 + t * 15)
        cg = int(30 + t * 60)
        cb = int(70 + t * 50)
        draw.line([(0, y), (SIZE, y)], fill=(cr, cg, cb, 255))

    # Apply rounded rect mask
    mask = rounded_rect_mask(SIZE, r)
    bg = img.copy()
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    img.paste(bg, mask=mask)
    draw = ImageDraw.Draw(img)

    # Draw broom
    cx, cy = SIZE // 2, SIZE // 2

    # --- Handle (diagonal line, top-right to center) ---
    handle_top_x = cx + int(SIZE * 0.22)
    handle_top_y = cy - int(SIZE * 0.28)
    handle_bot_x = cx - int(SIZE * 0.08)
    handle_bot_y = cy + int(SIZE * 0.12)
    handle_width = int(SIZE * 0.035)

    # Draw handle as a thick line (warm wood color)
    handle_color = (200, 165, 120, 255)
    draw.line(
        [(handle_top_x, handle_top_y), (handle_bot_x, handle_bot_y)],
        fill=handle_color, width=handle_width
    )
    # Handle cap (small circle at top)
    cap_r = int(handle_width * 0.7)
    draw.ellipse(
        [handle_top_x - cap_r, handle_top_y - cap_r,
         handle_top_x + cap_r, handle_top_y + cap_r],
        fill=(180, 145, 100, 255)
    )

    # --- Bristle binding (where handle meets bristles) ---
    bind_cx = handle_bot_x
    bind_cy = handle_bot_y
    bind_w = int(SIZE * 0.12)
    bind_h = int(SIZE * 0.04)
    # Rotate the binding to match handle angle
    # Draw as a small rectangle
    draw.ellipse(
        [bind_cx - bind_w, bind_cy - bind_h,
         bind_cx + bind_w, bind_cy + bind_h],
        fill=(160, 140, 100, 255)
    )

    # --- Bristles (fan shape below binding) ---
    bristle_color_main = (230, 200, 100, 255)
    bristle_color_dark = (200, 170, 70, 255)
    bristle_color_light = (245, 220, 130, 255)

    bristle_start_y = bind_cy + int(SIZE * 0.02)
    bristle_end_y = cy + int(SIZE * 0.32)
    bristle_spread = int(SIZE * 0.22)
    num_bristles = 15

    for i in range(num_bristles):
        t = i / (num_bristles - 1)  # 0 to 1
        # Fan out from center
        offset_x = int((t - 0.5) * 2 * bristle_spread)

        # Slight curve
        curve = int(abs(t - 0.5) * 2 * SIZE * 0.03)

        start_x = bind_cx + int(offset_x * 0.2)
        end_x = bind_cx + offset_x
        end_y = bristle_end_y + curve

        # Alternate colors
        if i % 3 == 0:
            color = bristle_color_dark
        elif i % 3 == 1:
            color = bristle_color_main
        else:
            color = bristle_color_light

        width = int(SIZE * 0.012)
        draw.line(
            [(start_x, bristle_start_y), (end_x, end_y)],
            fill=color, width=width
        )

    # --- Sparkle effects (to suggest "cleaning/scanning") ---
    sparkle_color = (255, 255, 255, 200)
    sparkles = [
        (cx - int(SIZE * 0.25), cy - int(SIZE * 0.15), int(SIZE * 0.04)),
        (cx - int(SIZE * 0.30), cy + int(SIZE * 0.05), int(SIZE * 0.025)),
        (cx - int(SIZE * 0.18), cy + int(SIZE * 0.20), int(SIZE * 0.03)),
        (cx + int(SIZE * 0.28), cy + int(SIZE * 0.15), int(SIZE * 0.02)),
        (cx - int(SIZE * 0.32), cy - int(SIZE * 0.05), int(SIZE * 0.015)),
    ]

    for sx, sy, sr in sparkles:
        # Draw 4-point star
        draw.line([(sx - sr, sy), (sx + sr, sy)], fill=sparkle_color, width=max(2, sr // 4))
        draw.line([(sx, sy - sr), (sx, sy + sr)], fill=sparkle_color, width=max(2, sr // 4))
        # Center dot
        dot_r = max(1, sr // 4)
        draw.ellipse([sx - dot_r, sy - dot_r, sx + dot_r, sy + dot_r], fill=(255, 255, 255, 240))

    # --- Subtle sweep motion lines ---
    motion_color = (255, 255, 255, 60)
    for i in range(3):
        y_off = int(SIZE * 0.22) + i * int(SIZE * 0.06)
        x_start = cx - int(SIZE * 0.35)
        x_end = cx - int(SIZE * 0.15) - i * int(SIZE * 0.03)
        draw.arc(
            [x_start, cy + y_off - int(SIZE * 0.05),
             x_end, cy + y_off + int(SIZE * 0.05)],
            start=160, end=200,
            fill=motion_color, width=int(SIZE * 0.006)
        )

    return img

def create_iconset(img, output_dir):
    """Create .iconset directory with all required sizes."""
    iconset_dir = os.path.join(output_dir, "AppIcon.iconset")
    os.makedirs(iconset_dir, exist_ok=True)

    sizes = [
        (16, 1), (16, 2),
        (32, 1), (32, 2),
        (128, 1), (128, 2),
        (256, 1), (256, 2),
        (512, 1), (512, 2),
    ]

    for size, scale in sizes:
        px = size * scale
        resized = img.resize((px, px), Image.LANCZOS)
        if scale == 1:
            name = f"icon_{size}x{size}.png"
        else:
            name = f"icon_{size}x{size}@2x.png"
        resized.save(os.path.join(iconset_dir, name))

    return iconset_dir

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_dir = os.path.dirname(script_dir)
    resources_dir = os.path.join(project_dir, "Resources")
    os.makedirs(resources_dir, exist_ok=True)

    print("Generating icon...")
    icon = draw_icon()

    # Save full-size PNG
    png_path = os.path.join(resources_dir, "AppIcon.png")
    icon.save(png_path)
    print(f"Saved {png_path}")

    # Create iconset
    iconset_dir = create_iconset(icon, resources_dir)
    print(f"Created {iconset_dir}")

    # Convert to .icns
    icns_path = os.path.join(resources_dir, "AppIcon.icns")
    result = subprocess.run(
        ["iconutil", "-c", "icns", iconset_dir, "-o", icns_path],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        print(f"Created {icns_path}")
        # Clean up iconset directory
        import shutil
        shutil.rmtree(iconset_dir)
    else:
        print(f"iconutil failed: {result.stderr}")

    print("Done!")
