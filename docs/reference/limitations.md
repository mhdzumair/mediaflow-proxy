# Limitations


- **Commercial DRM not supported**: Widevine, PlayReady, and FairPlay DRM systems require license server communication and hardware security modules. These cannot be decrypted by MediaFlow Proxy as they are designed to prevent unauthorized access.
- **Key rotation not supported**: Streams where encryption keys change mid-playback are not supported.
- **Only ClearKey DRM**: The proxy can only decrypt content where you already have the decryption keys (ClearKey/AES-128).
