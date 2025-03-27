#!/usr/bin/env python3
"""
Script to generate application icons for Network Traffic Analyzer.
This creates simple icons for use with the executable.
"""

import os
import io
import math
from PIL import Image, ImageDraw

def generate_app_icon():
    """Generate a simple network traffic analyzer icon"""
    # Create directories if they don't exist
    if not os.path.exists('icons'):
        os.makedirs('icons')
    
    # Icon sizes needed for various platforms
    sizes = [16, 32, 48, 64, 128, 256, 512]
    
    for size in sizes:
        # Create a blank image with an alpha channel
        image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        
        # Calculate scaling factors
        padding = math.floor(size * 0.1)
        center = size // 2
        radius = (size - 2 * padding) // 2
        
        # Draw a network globe
        draw.ellipse(
            (padding, padding, size - padding, size - padding),
            outline=(0, 120, 212, 255),  # Blue outline
            fill=(0, 120, 212, 100),     # Semi-transparent blue fill
            width=max(1, size // 32)
        )
        
        # Draw network connections
        dot_size = max(2, size // 16)
        # Small dots representing nodes
        positions = [
            (center - radius//2, center - radius//2),  # Top left
            (center + radius//2, center - radius//2),  # Top right
            (center, center + radius//2),             # Bottom center
            (center, center)                          # Center
        ]
        
        # Draw nodes
        for pos in positions:
            x, y = pos
            dot_radius = dot_size
            draw.ellipse(
                (x - dot_radius, y - dot_radius, x + dot_radius, y + dot_radius),
                fill=(255, 255, 255, 255)  # White dots
            )
        
        # Draw connections between nodes
        line_width = max(1, size // 64)
        # Connect to center
        center_pos = positions[-1]
        for i in range(len(positions) - 1):
            draw.line(
                [positions[i], center_pos],
                fill=(255, 255, 255, 200),
                width=line_width
            )
        
        # Add traffic flow indicator
        arrow_size = size // 8
        draw.polygon(
            [
                (center + arrow_size, center),
                (center, center - arrow_size//2),
                (center, center + arrow_size//2)
            ],
            fill=(255, 100, 100, 255)  # Red arrow
        )
        
        # Save as PNG
        png_path = os.path.join('icons', f'app_icon_{size}x{size}.png')
        image.save(png_path)
        print(f"Generated icon: {png_path}")
    
    # Create ICO file for Windows
    ico_path = os.path.join('icons', 'app_icon.ico')
    images = []
    for size in [16, 32, 48, 256]:
        img_path = os.path.join('icons', f'app_icon_{size}x{size}.png')
        if os.path.exists(img_path):
            img = Image.open(img_path)
            images.append(img)
    
    # Save as ICO if we have images
    if images:
        img_bytes = io.BytesIO()
        images[0].save(
            img_bytes, 
            format='ICO', 
            sizes=[(img.width, img.height) for img in images]
        )
        with open(ico_path, 'wb') as icon_file:
            icon_file.write(img_bytes.getvalue())
        print(f"Generated ICO file: {ico_path}")
    
    # Create ICNS file for macOS
    # Note: This is a simplified approach, a full ICNS file would need multiple image sizes
    largest_png = os.path.join('icons', f'app_icon_512x512.png')
    if os.path.exists(largest_png):
        icns_path = os.path.join('icons', 'app_icon.icns')
        try:
            # For real ICNS creation, you would use iconutil or similar tools
            # This is just copying the PNG for demonstration
            import shutil
            shutil.copy(largest_png, icns_path)
            print(f"Created placeholder ICNS file: {icns_path}")
            print("Note: For a proper ICNS file, you would need to use iconutil on macOS")
        except Exception as e:
            print(f"Could not create ICNS file: {e}")

if __name__ == "__main__":
    generate_app_icon()
    print("Icon generation complete. Icons are in the 'icons' directory.")