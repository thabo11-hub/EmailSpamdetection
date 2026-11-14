"""Builds the zip files the tests read. Run: python3 tests/fixtures/make_fixtures.py"""
import io, struct, zipfile, pathlib
here = pathlib.Path(__file__).parent

def build(entries):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return bytearray(buf.getvalue())

def central_dir(b):
    i = len(b) - 22
    while struct.unpack_from('<I', b, i)[0] != 0x06054b50:
        i -= 1
    return struct.unpack_from('<I', b, i + 16)[0]

(here / 'report.zip').write_bytes(build([('report.pdf', b'%PDF-1.4 hello')]))
(here / 'evil.zip').write_bytes(build([('invoice.pdf', b'%PDF-1.4'), ('payment.js', b'WScript.Echo(1)')]))

locked = build([('secret.docx', b'PK fake docx')])
cd = central_dir(locked)
struct.pack_into('<H', locked, cd + 8, struct.unpack_from('<H', locked, cd + 8)[0] | 1)   # "encrypted" flag
struct.pack_into('<H', locked, 6, struct.unpack_from('<H', locked, 6)[0] | 1)             # same in the local header
(here / 'locked.zip').write_bytes(locked)

bomb = build([('data.bin', b'\0' * 1000)])
cd = central_dir(bomb)
struct.pack_into('<I', bomb, cd + 24, 0x7FFFFFF0)                                        # claims 2 GB unpacked
(here / 'bomb.zip').write_bytes(bomb)
print('fixtures written')
