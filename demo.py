import os, re, pathlib, shutil, sys
from urllib.request import urlopen

MD_PATH = pathlib.Path("Writeups/write-ups.md")     # chỉnh nếu khác
IMG_DIR = MD_PATH.parent / "img"
IMG_DIR.mkdir(parents=True, exist_ok=True)

md = MD_PATH.read_text(encoding="utf-8")

pattern = re.compile(r'!\[([^\]]*)\]\((https?://user-images\.githubusercontent\.com/[^\s)]+)\)')
changed = False

def safe_name(url: str) -> str:
    # Lấy đuôi và tạo tên gọn từ đoạn cuối URL
    tail = url.split("/")[-1]
    # Nếu tên quá dài, cắt bớt
    if len(tail) > 64:
        name, dot, ext = tail.partition(".")
        tail = (name[:40] + "_clip") + (("." + ext) if ext else "")
    return tail

def download(url: str, out_path: pathlib.Path):
    with urlopen(url) as r, open(out_path, "wb") as f:
        shutil.copyfileobj(r, f)

def repl(m):
    global changed
    alt, url = m.group(1), m.group(2)
    local_name = safe_name(url)
    local_path = IMG_DIR / local_name
    if not local_path.exists():
        print(f"Downloading: {url} -> {local_path}")
        download(url, local_path)
    changed = True
    rel = f"img/{local_name}"
    return f"![{alt}]({rel})"

new_md = pattern.sub(repl, md)

if changed:
    MD_PATH.write_text(new_md, encoding="utf-8")
    print("Updated markdown links to local files.")
else:
    print("No user-images links found or nothing changed.")
