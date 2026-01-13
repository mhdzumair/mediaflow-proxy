import base64
import logging
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def is_base64_url(url: str) -> bool:
    """
    Check if a URL appears to be base64 encoded.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL appears to be base64 encoded, False otherwise.
    """
    # Check if the URL doesn't start with http/https and contains base64-like characters
    if url.startswith(("http://", "https://", "ftp://", "ftps://")):
        return False

    # Base64 URLs typically contain only alphanumeric characters, +, /, and =
    # and don't contain typical URL characters like ://
    base64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    url_chars = set(url)

    # If the URL contains characters not in base64 charset, it's likely not base64
    if not url_chars.issubset(base64_chars):
        return False

    # Additional heuristic: base64 strings are typically longer and don't contain common URL patterns
    if len(url) < 10:  # Too short to be a meaningful base64 encoded URL
        return False

    return True


def decode_base64_url(encoded_url: str) -> Optional[str]:
    """
    Decode a base64 encoded URL.

    Args:
        encoded_url (str): The base64 encoded URL string.

    Returns:
        Optional[str]: The decoded URL if successful, None if decoding fails.
    """
    try:
        # Handle URL-safe base64 encoding (replace - with + and _ with /)
        url_safe_encoded = encoded_url.replace("-", "+").replace("_", "/")

        # Add padding if necessary
        missing_padding = len(url_safe_encoded) % 4
        if missing_padding:
            url_safe_encoded += "=" * (4 - missing_padding)

        # Decode the base64 string
        decoded_bytes = base64.b64decode(url_safe_encoded)
        decoded_url = decoded_bytes.decode("utf-8")

        # Validate that the decoded string is a valid URL
        parsed = urlparse(decoded_url)
        if parsed.scheme and parsed.netloc:
            logger.info(f"Successfully decoded base64 URL: {encoded_url[:50]}... -> {decoded_url}")
            return decoded_url
        else:
            logger.warning(f"Decoded string is not a valid URL: {decoded_url}")
            return None

    except (base64.binascii.Error, UnicodeDecodeError, ValueError) as e:
        logger.debug(f"Failed to decode base64 URL '{encoded_url[:50]}...': {e}")
        return None


def encode_url_to_base64(url: str, url_safe: bool = True) -> str:
    """
    Encode a URL to base64.

    Args:
        url (str): The URL to encode.
        url_safe (bool): Whether to use URL-safe base64 encoding (default: True).

    Returns:
        str: The base64 encoded URL.
    """
    try:
        url_bytes = url.encode("utf-8")
        if url_safe:
            # Use URL-safe base64 encoding (replace + with - and / with _)
            encoded = base64.urlsafe_b64encode(url_bytes).decode("utf-8")
            # Remove padding for cleaner URLs
            encoded = encoded.rstrip("=")
        else:
            encoded = base64.b64encode(url_bytes).decode("utf-8")

        logger.debug(f"Encoded URL to base64: {url} -> {encoded}")
        return encoded

    except Exception as e:
        logger.error(f"Failed to encode URL to base64: {e}")
        raise


def process_potential_base64_url(url: str) -> str:
    """
    Process a URL that might be base64 encoded. If it's base64 encoded, decode it.
    Otherwise, return the original URL.

    Args:
        url (str): The URL to process.

    Returns:
        str: The processed URL (decoded if it was base64, original otherwise).
    """
    if is_base64_url(url):
        decoded_url = decode_base64_url(url)
        if decoded_url:
            return decoded_url
        else:
            logger.warning(f"URL appears to be base64 but failed to decode: {url[:50]}...")

    return url
