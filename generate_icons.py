import os
from PIL import Image

sizes = [72, 96, 128, 144, 152, 192, 384, 512]
base_dir = r"c:\Users\MAC-LAB3-C5\Desktop\RedEye\app\static\img"
icons_dir = os.path.join(base_dir, "icons")
os.makedirs(icons_dir, exist_ok=True)

try:
    img = Image.open(os.path.join(base_dir, "redeye.png"))
    
    # Ensure it's a square aspect ratio by padding with transparency if needed, 
    # but the logo is likely already square or close to it.
    width, height = img.size
    
    for size in sizes:
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        resized.save(os.path.join(icons_dir, f"icon-{size}x{size}.png"))
        
    print("PWA icons generated successfully!")
except Exception as e:
    print(f"Error: {e}")
