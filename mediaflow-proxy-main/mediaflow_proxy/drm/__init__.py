import os
import tempfile


async def create_temp_file(suffix: str, content: bytes = None, prefix: str = None) -> tempfile.NamedTemporaryFile:
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix=prefix)
    temp_file.delete_file = lambda: os.unlink(temp_file.name)
    if content:
        temp_file.write(content)
        temp_file.close()
    return temp_file
