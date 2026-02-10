import argparse
import struct
import sys
from typing import Optional, Union

from Crypto.Cipher import AES
from collections import namedtuple
import array

CENCSampleAuxiliaryDataFormat = namedtuple("CENCSampleAuxiliaryDataFormat", ["is_encrypted", "iv", "sub_samples"])


class MP4Atom:
    """
    Represents an MP4 atom, which is a basic unit of data in an MP4 file.
    Each atom contains a header (size and type) and data.
    """

    __slots__ = ("atom_type", "size", "data")

    def __init__(self, atom_type: bytes, size: int, data: Union[memoryview, bytearray]):
        """
        Initializes an MP4Atom instance.

        Args:
            atom_type (bytes): The type of the atom.
            size (int): The size of the atom.
            data (Union[memoryview, bytearray]): The data contained in the atom.
        """
        self.atom_type = atom_type
        self.size = size
        self.data = data

    def __repr__(self):
        return f"<MP4Atom type={self.atom_type}, size={self.size}>"

    def pack(self):
        """
        Packs the atom into binary data.

        Returns:
            bytes: Packed binary data with size, type, and data.
        """
        return struct.pack(">I", self.size) + self.atom_type + self.data


class MP4Parser:
    """
    Parses MP4 data to extract atoms and their structure.
    """

    def __init__(self, data: memoryview):
        """
        Initializes an MP4Parser instance.

        Args:
            data (memoryview): The binary data of the MP4 file.
        """
        self.data = data
        self.position = 0

    def read_atom(self) -> Optional[MP4Atom]:
        """
        Reads the next atom from the data.

        Returns:
            Optional[MP4Atom]: MP4Atom object or None if no more atoms are available.
        """
        pos = self.position
        if pos + 8 > len(self.data):
            return None

        size, atom_type = struct.unpack_from(">I4s", self.data, pos)
        pos += 8

        if size == 1:
            if pos + 8 > len(self.data):
                return None
            size = struct.unpack_from(">Q", self.data, pos)[0]
            pos += 8

        if size < 8 or pos + size - 8 > len(self.data):
            return None

        atom_data = self.data[pos : pos + size - 8]
        self.position = pos + size - 8
        return MP4Atom(atom_type, size, atom_data)

    def list_atoms(self) -> list[MP4Atom]:
        """
        Lists all atoms in the data.

        Returns:
            list[MP4Atom]: List of MP4Atom objects.
        """
        atoms = []
        original_position = self.position
        self.position = 0
        while self.position + 8 <= len(self.data):
            atom = self.read_atom()
            if not atom:
                break
            atoms.append(atom)
        self.position = original_position
        return atoms

    def _read_atom_at(self, pos: int, end: int) -> Optional[MP4Atom]:
        if pos + 8 > end:
            return None

        size, atom_type = struct.unpack_from(">I4s", self.data, pos)
        pos += 8

        if size == 1:
            if pos + 8 > end:
                return None
            size = struct.unpack_from(">Q", self.data, pos)[0]
            pos += 8

        if size < 8 or pos + size - 8 > end:
            return None

        atom_data = self.data[pos : pos + size - 8]
        return MP4Atom(atom_type, size, atom_data)

    def print_atoms_structure(self, indent: int = 0):
        """
        Prints the structure of all atoms in the data.

        Args:
            indent (int): The indentation level for printing.
        """
        pos = 0
        end = len(self.data)
        while pos + 8 <= end:
            atom = self._read_atom_at(pos, end)
            if not atom:
                break
            self.print_single_atom_structure(atom, pos, indent)
            pos += atom.size

    def print_single_atom_structure(self, atom: MP4Atom, parent_position: int, indent: int):
        """
        Prints the structure of a single atom.

        Args:
            atom (MP4Atom): The atom to print.
            parent_position (int): The position of the parent atom.
            indent (int): The indentation level for printing.
        """
        try:
            atom_type = atom.atom_type.decode("utf-8")
        except UnicodeDecodeError:
            atom_type = repr(atom.atom_type)
        print(" " * indent + f"Type: {atom_type}, Size: {atom.size}")

        child_pos = 0
        child_end = len(atom.data)
        while child_pos + 8 <= child_end:
            child_atom = self._read_atom_at(parent_position + 8 + child_pos, parent_position + 8 + child_end)
            if not child_atom:
                break
            self.print_single_atom_structure(child_atom, parent_position, indent + 2)
            child_pos += child_atom.size


class MP4Decrypter:
    """
    Class to handle the decryption of CENC encrypted MP4 segments.

    Supports multi-track segments (e.g., video + audio) by properly handling
    data offsets and encryption info for each track.

    Attributes:
        key_map (dict[bytes, bytes]): Mapping of KIDs to decryption keys.
        current_key (Optional[bytes]): Current decryption key (for single-track compatibility).
        trun_sample_sizes (array.array): Array of sample sizes from the 'trun' box.
        current_sample_info (list): List of sample information from the 'senc' box.
        total_encryption_overhead (int): Total size of encryption-related boxes (senc, saiz, saio) across all trafs.
        default_sample_size (int): Default sample size from tfhd, used when trun doesn't specify sizes.
        track_infos (list): List of track info dicts for multi-track mdat decryption.
        encryption_scheme (bytes): Encryption scheme type (b"cenc", b"cens", b"cbc1", or b"cbcs").
        crypt_byte_block (int): Number of encrypted 16-byte blocks in pattern encryption (for cbcs).
        skip_byte_block (int): Number of clear 16-byte blocks in pattern encryption (for cbcs).
    """

    def __init__(self, key_map: dict[bytes, bytes]):
        """
        Initializes the MP4Decrypter with a key map.

        Args:
            key_map (dict[bytes, bytes]): Mapping of track IDs to decryption keys.
        """
        self.key_map = key_map
        self.current_key = None
        self.trun_sample_sizes = array.array("I")
        self.current_sample_info = []
        self.total_encryption_overhead = 0  # Total overhead from all trafs (senc, saiz, saio)
        self.default_sample_size = 0
        # Track info for multi-track support: list of (data_offset, sample_sizes, sample_info, key, default_sample_size)
        self.track_infos = []
        # IV size from tenc box (default 8 for GPAC, 16 for Bento4)
        self.default_iv_size = 8
        # Encryption scheme: b"cenc" (AES-CTR), b"cens" (AES-CTR pattern), b"cbc1" (AES-CBC), b"cbcs" (AES-CBC pattern)
        self.encryption_scheme = b"cenc"  # Default to cenc (AES-CTR)
        # Pattern encryption parameters (for cbcs/cens) - default values
        self.crypt_byte_block = 1  # Default: encrypt 1 block
        self.skip_byte_block = 9  # Default: skip 9 blocks
        # Constant IV for CBCS (when default_Per_Sample_IV_Size is 0)
        self.constant_iv: Optional[bytes] = None
        # Per-track encryption settings (track_id -> {crypt, skip, iv})
        self.track_encryption_settings: dict[int, dict] = {}
        # Extracted KIDs from tenc boxes (track_id -> kid)
        self.extracted_kids: dict[int, bytes] = {}
        # Current track ID being processed
        self.current_track_id: int = 0

    def decrypt_segment(self, combined_segment: bytes, include_init: bool = True) -> bytes:
        """
        Decrypts a combined MP4 segment.

        Args:
            combined_segment (bytes): Combined initialization and media segment.
            include_init (bool): If True, include processed init atoms (ftyp, moov) in output.
                If False, only return media atoms (moof, sidx, mdat) for use with EXT-X-MAP.

        Returns:
            bytes: Decrypted segment content.
        """
        data = memoryview(combined_segment)
        parser = MP4Parser(data)
        atoms = parser.list_atoms()

        atom_process_order = [b"moov", b"moof", b"sidx", b"mdat"]

        processed_atoms = {}
        for atom_type in atom_process_order:
            if atom := next((a for a in atoms if a.atom_type == atom_type), None):
                processed_atoms[atom_type] = self._process_atom(atom_type, atom)

        result = bytearray()
        # Init atoms to skip when include_init is False
        # Note: styp is a segment type atom that should be kept in segments
        init_atoms = {b"ftyp", b"moov"}

        for atom in atoms:
            # Skip init atoms if not including init
            if not include_init and atom.atom_type in init_atoms:
                continue

            if atom.atom_type in processed_atoms:
                processed_atom = processed_atoms[atom.atom_type]
                result.extend(processed_atom.pack())
            else:
                result.extend(atom.pack())

        return bytes(result)

    def process_init_only(self, init_segment: bytes) -> bytes:
        """
        Processes only the initialization segment, removing encryption-related boxes.
        Used for EXT-X-MAP where init is served separately.

        Args:
            init_segment (bytes): Initialization segment data.

        Returns:
            bytes: Processed init segment with encryption boxes removed.
        """
        data = memoryview(init_segment)
        parser = MP4Parser(data)
        atoms = parser.list_atoms()

        processed_atoms = {}
        # Only process moov for init segments
        if moov_atom := next((a for a in atoms if a.atom_type == b"moov"), None):
            processed_atoms[b"moov"] = self._process_moov(moov_atom)

        result = bytearray()
        for atom in atoms:
            if atom.atom_type in processed_atoms:
                processed_atom = processed_atoms[atom.atom_type]
                result.extend(processed_atom.pack())
            else:
                result.extend(atom.pack())

        return bytes(result)

    def _process_atom(self, atom_type: bytes, atom: MP4Atom) -> MP4Atom:
        """
        Processes an MP4 atom based on its type.

        Args:
            atom_type (bytes): Type of the atom.
            atom (MP4Atom): The atom to process.

        Returns:
            MP4Atom: Processed atom.
        """
        if atom_type == b"moov":
            return self._process_moov(atom)
        elif atom_type == b"moof":
            return self._process_moof(atom)
        elif atom_type == b"sidx":
            return self._process_sidx(atom)
        elif atom_type == b"mdat":
            return self._decrypt_mdat(atom)
        else:
            return atom

    def _process_moov(self, moov: MP4Atom) -> MP4Atom:
        """
        Processes the 'moov' (Movie) atom, which contains metadata about the entire presentation.
        This includes information about tracks, media data, and other movie-level metadata.

        Args:
            moov (MP4Atom): The 'moov' atom to process.

        Returns:
            MP4Atom: Processed 'moov' atom with updated track information.
        """
        parser = MP4Parser(moov.data)
        new_moov_data = bytearray()

        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"trak":
                new_trak = self._process_trak(atom)
                new_moov_data.extend(new_trak.pack())
            elif atom.atom_type != b"pssh":
                # Skip PSSH boxes as they are not needed in the decrypted output
                new_moov_data.extend(atom.pack())

        return MP4Atom(b"moov", len(new_moov_data) + 8, new_moov_data)

    def _process_moof(self, moof: MP4Atom) -> MP4Atom:
        """
        Processes the 'moof' (Movie Fragment) atom, which contains metadata about a fragment.
        This includes information about track fragments, sample information, and encryption data.

        Args:
            moof (MP4Atom): The 'moof' atom to process.

        Returns:
            MP4Atom: Processed 'moof' atom with updated track information.
        """
        parser = MP4Parser(moof.data)
        atoms = parser.list_atoms()

        # Reset track infos for this moof
        self.track_infos = []

        # First pass: calculate total encryption overhead from all trafs
        self.total_encryption_overhead = 0
        for atom in atoms:
            if atom.atom_type == b"traf":
                traf_parser = MP4Parser(atom.data)
                traf_atoms = traf_parser.list_atoms()
                traf_overhead = sum(a.size for a in traf_atoms if a.atom_type in {b"senc", b"saiz", b"saio"})
                self.total_encryption_overhead += traf_overhead

        # Second pass: process atoms
        new_moof_data = bytearray()
        for atom in atoms:
            if atom.atom_type == b"traf":
                new_traf = self._process_traf(atom)
                new_moof_data.extend(new_traf.pack())
            else:
                new_moof_data.extend(atom.pack())

        return MP4Atom(b"moof", len(new_moof_data) + 8, new_moof_data)

    def _process_traf(self, traf: MP4Atom) -> MP4Atom:
        """
        Processes the 'traf' (Track Fragment) atom, which contains information about a track fragment.
        This includes sample information, sample encryption data, and other track-level metadata.

        Args:
            traf (MP4Atom): The 'traf' atom to process.

        Returns:
            MP4Atom: Processed 'traf' atom with updated sample information.
        """
        parser = MP4Parser(traf.data)
        new_traf_data = bytearray()
        tfhd = None
        sample_count = 0
        trun_data_offset = 0
        sample_info = []
        track_default_sample_size = 0

        atoms = parser.list_atoms()

        for atom in atoms:
            if atom.atom_type == b"tfhd":
                tfhd = atom
                new_traf_data.extend(atom.pack())
                # Extract default_sample_size from tfhd if present
                self._parse_tfhd(atom)
                track_default_sample_size = self.default_sample_size
            elif atom.atom_type == b"trun":
                sample_count, trun_data_offset = self._process_trun(atom)
                new_trun = self._modify_trun(atom)
                new_traf_data.extend(new_trun.pack())
            elif atom.atom_type == b"senc":
                # Parse senc but don't include it in the new decrypted traf data and similarly don't include saiz and saio
                sample_info = self._parse_senc(atom, sample_count)
            elif atom.atom_type not in {b"saiz", b"saio"}:
                new_traf_data.extend(atom.pack())

        if tfhd:
            tfhd_track_id = struct.unpack_from(">I", tfhd.data, 4)[0]
            track_key = self._get_key_for_track(tfhd_track_id)
            # Get per-track encryption settings if available
            track_enc_settings = self.track_encryption_settings.get(tfhd_track_id, {})
            # Store track info for multi-track mdat decryption
            # Copy the sample sizes array since it gets overwritten for each track
            track_sample_sizes = array.array("I", self.trun_sample_sizes)
            self.track_infos.append(
                {
                    "data_offset": trun_data_offset,
                    "sample_sizes": track_sample_sizes,
                    "sample_info": sample_info,
                    "key": track_key,
                    "default_sample_size": track_default_sample_size,
                    "track_id": tfhd_track_id,
                    "crypt_byte_block": track_enc_settings.get("crypt_byte_block", self.crypt_byte_block),
                    "skip_byte_block": track_enc_settings.get("skip_byte_block", self.skip_byte_block),
                    "constant_iv": track_enc_settings.get("constant_iv", self.constant_iv),
                }
            )
            # Keep backward compatibility for single-track case
            self.current_key = track_key
            self.current_sample_info = sample_info

        return MP4Atom(b"traf", len(new_traf_data) + 8, new_traf_data)

    def _parse_tfhd(self, tfhd: MP4Atom) -> None:
        """
        Parses the 'tfhd' (Track Fragment Header) atom to extract default sample size.

        Args:
            tfhd (MP4Atom): The 'tfhd' atom to parse.
        """
        data = tfhd.data
        flags = struct.unpack_from(">I", data, 0)[0] & 0xFFFFFF
        offset = 8  # Skip version_flags (4) + track_id (4)

        # Skip optional fields based on flags
        if flags & 0x000001:  # base-data-offset-present
            offset += 8
        if flags & 0x000002:  # sample-description-index-present
            offset += 4
        if flags & 0x000008:  # default-sample-duration-present
            offset += 4
        if flags & 0x000010:  # default-sample-size-present
            if offset + 4 <= len(data):
                self.default_sample_size = struct.unpack_from(">I", data, offset)[0]
            offset += 4
        # We don't need default-sample-flags (0x000020)

    def _decrypt_mdat(self, mdat: MP4Atom) -> MP4Atom:
        """
        Decrypts the 'mdat' (Media Data) atom, which contains the actual media data (audio, video, etc.).
        The decryption is performed using the current decryption key and sample information.
        Supports multiple tracks by using track_infos collected during moof processing.

        Args:
            mdat (MP4Atom): The 'mdat' atom to decrypt.

        Returns:
            MP4Atom: Decrypted 'mdat' atom with decrypted media data.
        """
        mdat_data = mdat.data

        # Use multi-track decryption if we have track_infos
        if self.track_infos:
            return self._decrypt_mdat_multi_track(mdat)

        # Fallback to single-track decryption for backward compatibility
        if not self.current_key or not self.current_sample_info:
            return mdat  # Return original mdat if we don't have decryption info

        decrypted_samples = bytearray()
        position = 0

        for i, info in enumerate(self.current_sample_info):
            if position >= len(mdat_data):
                break  # No more data to process

            # Get sample size from trun, or use default_sample_size from tfhd, or remaining data
            sample_size = 0
            if i < len(self.trun_sample_sizes):
                sample_size = self.trun_sample_sizes[i]

            # If sample size is 0 (not specified in trun), use default from tfhd
            if sample_size == 0:
                sample_size = self.default_sample_size if self.default_sample_size > 0 else len(mdat_data) - position

            sample = mdat_data[position : position + sample_size]
            position += sample_size
            decrypted_sample = self._decrypt_sample(sample, info, self.current_key)
            decrypted_samples.extend(decrypted_sample)

        return MP4Atom(b"mdat", len(decrypted_samples) + 8, decrypted_samples)

    def _decrypt_mdat_multi_track(self, mdat: MP4Atom) -> MP4Atom:
        """
        Decrypts the 'mdat' atom with support for multiple tracks.
        Each track's samples are located at their respective data_offset positions.

        The data_offset in trun is the byte offset from the start of the moof box
        to the first byte of sample data. Since mdat immediately follows moof,
        we can calculate the position within mdat as:
        position_in_mdat = data_offset - moof_size

        But we don't have moof_size here directly. However, we know that the first
        track's data_offset minus 8 (mdat header) gives us the moof size.

        For simplicity, we sort tracks by data_offset and process them in order,
        using the data_offset difference to determine where each track's samples start.

        Args:
            mdat (MP4Atom): The 'mdat' atom to decrypt.

        Returns:
            MP4Atom: Decrypted 'mdat' atom with decrypted media data from all tracks.
        """
        mdat_data = mdat.data

        if not self.track_infos:
            return mdat

        # Sort tracks by data_offset to process in order
        sorted_tracks = sorted(self.track_infos, key=lambda x: x["data_offset"])

        # The first track's data_offset tells us where mdat data starts relative to moof
        # data_offset = moof_size + 8 (mdat header) for the first sample
        # So mdat_data_start_in_file = moof_start + first_data_offset
        # And position_in_mdat = data_offset - first_data_offset
        first_data_offset = sorted_tracks[0]["data_offset"]

        # Pre-allocate output buffer with original data (in case some parts aren't encrypted)
        decrypted_data = bytearray(mdat_data)

        # Process each track's samples at their respective offsets
        for track_info in sorted_tracks:
            data_offset = track_info["data_offset"]
            sample_sizes = track_info["sample_sizes"]
            sample_info = track_info["sample_info"]
            key = track_info["key"]
            default_sample_size = track_info["default_sample_size"]
            # Get per-track encryption settings
            track_crypt = track_info.get("crypt_byte_block", self.crypt_byte_block)
            track_skip = track_info.get("skip_byte_block", self.skip_byte_block)
            track_constant_iv = track_info.get("constant_iv", self.constant_iv)

            if not key or not sample_info:
                continue

            # Calculate start position in mdat
            # position = data_offset - first_data_offset (relative to first track's start)
            mdat_position = data_offset - first_data_offset

            for i, info in enumerate(sample_info):
                sample_size = 0
                if i < len(sample_sizes):
                    sample_size = sample_sizes[i]

                if sample_size == 0:
                    sample_size = default_sample_size if default_sample_size > 0 else 0

                if sample_size == 0:
                    continue

                if mdat_position + sample_size > len(mdat_data):
                    break

                sample = mdat_data[mdat_position : mdat_position + sample_size]
                decrypted_sample = self._decrypt_sample_with_track_settings(
                    sample, info, key, track_crypt, track_skip, track_constant_iv
                )

                # Write decrypted sample to output at the same position
                decrypted_data[mdat_position : mdat_position + len(decrypted_sample)] = decrypted_sample
                mdat_position += sample_size

        return MP4Atom(b"mdat", len(decrypted_data) + 8, bytes(decrypted_data))

    def _parse_senc(self, senc: MP4Atom, sample_count: int) -> list[CENCSampleAuxiliaryDataFormat]:
        """
        Parses the 'senc' (Sample Encryption) atom, which contains encryption information for samples.
        This includes initialization vectors (IVs) and sub-sample encryption data.

        For CBCS with constant IV (default_iv_size == 0 in tenc), the senc box only contains
        subsample info, not per-sample IVs. The constant IV from tenc is used instead.

        Args:
            senc (MP4Atom): The 'senc' atom to parse.
            sample_count (int): The number of samples.

        Returns:
            list[CENCSampleAuxiliaryDataFormat]: List of sample auxiliary data formats with encryption information.
        """
        data = memoryview(senc.data)
        version_flags = struct.unpack_from(">I", data, 0)[0]
        version, flags = version_flags >> 24, version_flags & 0xFFFFFF
        position = 4

        if version == 0:
            sample_count = struct.unpack_from(">I", data, position)[0]
            position += 4

        # Use the IV size from tenc box (8 or 16 bytes, or 0 for constant IV)
        iv_size = self.default_iv_size

        # For CBCS with constant IV, use the IV from tenc instead of per-sample IVs
        use_constant_iv = self.encryption_scheme == b"cbcs" and self.constant_iv is not None

        sample_info = []
        for _ in range(sample_count):
            if use_constant_iv:
                # Use constant IV from tenc box
                iv = self.constant_iv
            else:
                # Read per-sample IV from senc
                if position + iv_size > len(data):
                    break
                iv = data[position : position + iv_size].tobytes()
                position += iv_size

            sub_samples = []
            if flags & 0x000002 and position + 2 <= len(data):  # Check if subsample information is present
                subsample_count = struct.unpack_from(">H", data, position)[0]
                position += 2

                for _ in range(subsample_count):
                    if position + 6 <= len(data):
                        clear_bytes, encrypted_bytes = struct.unpack_from(">HI", data, position)
                        position += 6
                        sub_samples.append((clear_bytes, encrypted_bytes))
                    else:
                        break

            sample_info.append(CENCSampleAuxiliaryDataFormat(True, iv, sub_samples))

        return sample_info

    def _get_key_for_track(self, track_id: int) -> bytes:
        """
        Retrieves the decryption key for a given track ID from the key map.
        Uses the KID extracted from the tenc box if available, otherwise falls back to
        using the first key if only one key is provided.

        Args:
            track_id (int): The track ID.

        Returns:
            bytes: The decryption key for the specified track ID.
        """
        # If we have an extracted KID for this track, use it to look up the key
        if track_id in self.extracted_kids:
            extracted_kid = self.extracted_kids[track_id]
            # If KID is all zeros, it's a placeholder - use the provided key_id directly
            # Check if all bytes are zero
            is_all_zeros = all(b == 0 for b in extracted_kid) and len(extracted_kid) == 16
            if is_all_zeros:
                # All zeros KID means use the provided key_id (first key in map)
                if len(self.key_map) == 1:
                    return next(iter(self.key_map.values()))
            else:
                # Use the extracted KID to look up the key
                key = self.key_map.get(extracted_kid)
                if key:
                    return key
                # If KID doesn't match, try fallback
                # Note: This is expected when KID in file doesn't match provided key_id
                # The provided key_id should still work if it's the correct decryption key

        # Fallback: if only one key provided, use it (backward compatibility)
        if len(self.key_map) == 1:
            return next(iter(self.key_map.values()))

        # Try using track_id as KID (for multi-key scenarios)
        track_id_bytes = track_id.to_bytes(4, "big")
        key = self.key_map.get(track_id_bytes)
        if not key:
            raise ValueError(f"No key found for track ID {track_id}")
        return key

    @staticmethod
    def _process_sample(
        sample: memoryview, sample_info: CENCSampleAuxiliaryDataFormat, key: bytes
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Processes and decrypts a sample using the provided sample information and decryption key.
        This includes handling sub-sample encryption if present.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format with encryption information.
            key (bytes): The decryption key.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if not sample_info.is_encrypted:
            return sample

        # pad IV to 16 bytes
        iv = sample_info.iv + b"\x00" * (16 - len(sample_info.iv))
        cipher = AES.new(key, AES.MODE_CTR, initial_value=iv, nonce=b"")

        if not sample_info.sub_samples:
            # If there are no sub_samples, decrypt the entire sample
            return cipher.decrypt(sample)

        result = bytearray()
        offset = 0
        for clear_bytes, encrypted_bytes in sample_info.sub_samples:
            result.extend(sample[offset : offset + clear_bytes])
            offset += clear_bytes
            result.extend(cipher.decrypt(sample[offset : offset + encrypted_bytes]))
            offset += encrypted_bytes

        # If there's any remaining data, treat it as encrypted
        if offset < len(sample):
            result.extend(cipher.decrypt(sample[offset:]))

        return result

    def _process_sample_cbcs(
        self, sample: memoryview, sample_info: CENCSampleAuxiliaryDataFormat, key: bytes
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Processes and decrypts a sample using CBCS (AES-CBC with pattern encryption).

        CBCS uses AES-CBC mode with a constant IV (no counter increment between blocks).
        Pattern encryption encrypts 'crypt_byte_block' 16-byte blocks, then leaves
        'skip_byte_block' 16-byte blocks in the clear, repeating this pattern.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format with encryption information.
            key (bytes): The decryption key.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if not sample_info.is_encrypted:
            return sample

        # CBCS uses constant IV - pad to 16 bytes
        iv = sample_info.iv + b"\x00" * (16 - len(sample_info.iv))

        if not sample_info.sub_samples:
            # Full sample encryption with pattern
            return self._decrypt_cbcs_pattern(bytes(sample), key, iv)

        # Subsample encryption
        result = bytearray()
        offset = 0
        for clear_bytes, encrypted_bytes in sample_info.sub_samples:
            # Copy clear bytes as-is
            result.extend(sample[offset : offset + clear_bytes])
            offset += clear_bytes

            # Decrypt encrypted portion using pattern encryption
            encrypted_part = bytes(sample[offset : offset + encrypted_bytes])
            decrypted = self._decrypt_cbcs_pattern(encrypted_part, key, iv)
            result.extend(decrypted)
            offset += encrypted_bytes

        # If there's any remaining data after subsamples, copy as-is (shouldn't happen)
        if offset < len(sample):
            result.extend(sample[offset:])

        return result

    def _decrypt_cbcs_pattern(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """
        Decrypts data using CBCS pattern encryption (AES-CBC with crypt/skip pattern).

        Pattern encryption decrypts 'crypt_byte_block' 16-byte blocks, then skips
        'skip_byte_block' 16-byte blocks (leaving them in clear), repeating.

        Important: In CBCS, the CBC cipher state (previous ciphertext) carries over
        between encrypted blocks, even though clear blocks are skipped. This means
        we need to collect all encrypted blocks, decrypt them as a continuous CBC
        stream, then interleave the results with the clear blocks.

        Args:
            data (bytes): The encrypted data.
            key (bytes): The decryption key.
            iv (bytes): The initialization vector.

        Returns:
            bytes: The decrypted data.
        """
        if not data:
            return data

        block_size = 16
        crypt_blocks = self.crypt_byte_block
        skip_blocks = self.skip_byte_block

        # If no pattern (crypt=0), no encryption
        if crypt_blocks == 0:
            return data

        # If skip=0, it's full encryption (all blocks encrypted)
        if skip_blocks == 0:
            # Decrypt complete blocks only
            complete_blocks_size = (len(data) // block_size) * block_size
            if complete_blocks_size > 0:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(data[:complete_blocks_size])
                if complete_blocks_size < len(data):
                    return decrypted + data[complete_blocks_size:]
                return decrypted
            return data

        crypt_bytes = crypt_blocks * block_size
        skip_bytes = skip_blocks * block_size

        # Step 1: Collect all encrypted blocks
        encrypted_blocks = bytearray()
        block_positions = []  # Track where each encrypted block came from
        pos = 0

        while pos < len(data):
            # Encrypted portion
            if pos + crypt_bytes <= len(data):
                encrypted_blocks.extend(data[pos : pos + crypt_bytes])
                block_positions.append((pos, crypt_bytes))
                pos += crypt_bytes
            else:
                # Remaining data - encrypt complete blocks only
                remaining = len(data) - pos
                complete = (remaining // block_size) * block_size
                if complete > 0:
                    encrypted_blocks.extend(data[pos : pos + complete])
                    block_positions.append((pos, complete))
                    pos += complete
                break

            # Skip clear portion
            if pos + skip_bytes <= len(data):
                pos += skip_bytes
            else:
                break

        # Step 2: Decrypt all encrypted blocks as a continuous CBC stream
        if encrypted_blocks:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_blocks = cipher.decrypt(bytes(encrypted_blocks))
        else:
            decrypted_blocks = b""

        # Step 3: Reconstruct the output with decrypted blocks and clear blocks
        result = bytearray(data)  # Start with original data
        decrypted_pos = 0

        for orig_pos, length in block_positions:
            result[orig_pos : orig_pos + length] = decrypted_blocks[decrypted_pos : decrypted_pos + length]
            decrypted_pos += length

        return bytes(result)

    def _process_sample_cbc1(
        self, sample: memoryview, sample_info: CENCSampleAuxiliaryDataFormat, key: bytes
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Processes and decrypts a sample using CBC1 (full sample AES-CBC encryption).

        Unlike CBCS, CBC1 encrypts the entire sample without pattern encryption.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format with encryption information.
            key (bytes): The decryption key.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if not sample_info.is_encrypted:
            return sample

        # Pad IV to 16 bytes
        iv = sample_info.iv + b"\x00" * (16 - len(sample_info.iv))
        cipher = AES.new(key, AES.MODE_CBC, iv)

        if not sample_info.sub_samples:
            # Full sample encryption - decrypt complete blocks only
            block_size = 16
            complete_blocks_size = (len(sample) // block_size) * block_size
            if complete_blocks_size > 0:
                decrypted = cipher.decrypt(bytes(sample[:complete_blocks_size]))
                if complete_blocks_size < len(sample):
                    # Append remaining partial block as-is
                    return decrypted + bytes(sample[complete_blocks_size:])
                return decrypted
            return sample

        # Subsample encryption
        result = bytearray()
        offset = 0
        for clear_bytes, encrypted_bytes in sample_info.sub_samples:
            result.extend(sample[offset : offset + clear_bytes])
            offset += clear_bytes

            encrypted_part = bytes(sample[offset : offset + encrypted_bytes])
            # Only decrypt complete blocks
            block_size = 16
            complete_blocks_size = (len(encrypted_part) // block_size) * block_size
            if complete_blocks_size > 0:
                decrypted = cipher.decrypt(encrypted_part[:complete_blocks_size])
                result.extend(decrypted)
                if complete_blocks_size < len(encrypted_part):
                    result.extend(encrypted_part[complete_blocks_size:])
            else:
                result.extend(encrypted_part)
            offset += encrypted_bytes

        if offset < len(sample):
            result.extend(sample[offset:])

        return result

    def _decrypt_sample(
        self, sample: memoryview, sample_info: CENCSampleAuxiliaryDataFormat, key: bytes
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Decrypts a sample using the appropriate scheme based on encryption_scheme attribute.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format.
            key (bytes): The decryption key.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if self.encryption_scheme == b"cbcs":
            return self._process_sample_cbcs(sample, sample_info, key)
        elif self.encryption_scheme == b"cbc1":
            return self._process_sample_cbc1(sample, sample_info, key)
        else:
            # cenc and cens use AES-CTR
            return self._process_sample(sample, sample_info, key)

    def _decrypt_sample_with_track_settings(
        self,
        sample: memoryview,
        sample_info: CENCSampleAuxiliaryDataFormat,
        key: bytes,
        crypt_byte_block: int,
        skip_byte_block: int,
        constant_iv: Optional[bytes],
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Decrypts a sample using per-track encryption settings.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format.
            key (bytes): The decryption key.
            crypt_byte_block (int): Number of encrypted blocks in pattern.
            skip_byte_block (int): Number of clear blocks in pattern.
            constant_iv (Optional[bytes]): Constant IV for CBCS, or None.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if self.encryption_scheme == b"cbcs":
            return self._process_sample_cbcs_with_settings(
                sample, sample_info, key, crypt_byte_block, skip_byte_block, constant_iv
            )
        elif self.encryption_scheme == b"cbc1":
            return self._process_sample_cbc1(sample, sample_info, key)
        else:
            # cenc and cens use AES-CTR
            return self._process_sample(sample, sample_info, key)

    def _process_sample_cbcs_with_settings(
        self,
        sample: memoryview,
        sample_info: CENCSampleAuxiliaryDataFormat,
        key: bytes,
        crypt_byte_block: int,
        skip_byte_block: int,
        constant_iv: Optional[bytes],
    ) -> Union[memoryview, bytearray, bytes]:
        """
        Processes and decrypts a sample using CBCS with per-track settings.

        Args:
            sample (memoryview): The sample data.
            sample_info (CENCSampleAuxiliaryDataFormat): The sample auxiliary data format.
            key (bytes): The decryption key.
            crypt_byte_block (int): Number of encrypted blocks in pattern.
            skip_byte_block (int): Number of clear blocks in pattern.
            constant_iv (Optional[bytes]): Constant IV for CBCS, or None.

        Returns:
            Union[memoryview, bytearray, bytes]: The decrypted sample.
        """
        if not sample_info.is_encrypted:
            return sample

        # Use constant IV if provided, otherwise use the IV from sample_info
        if constant_iv:
            iv = constant_iv + b"\x00" * (16 - len(constant_iv))
        else:
            iv = sample_info.iv + b"\x00" * (16 - len(sample_info.iv))

        if not sample_info.sub_samples:
            # Full sample encryption with pattern
            return self._decrypt_cbcs_pattern_with_settings(bytes(sample), key, iv, crypt_byte_block, skip_byte_block)

        # Subsample encryption
        result = bytearray()
        offset = 0
        for clear_bytes, encrypted_bytes in sample_info.sub_samples:
            # Copy clear bytes as-is
            result.extend(sample[offset : offset + clear_bytes])
            offset += clear_bytes

            # Decrypt encrypted portion using pattern encryption
            encrypted_part = bytes(sample[offset : offset + encrypted_bytes])
            decrypted = self._decrypt_cbcs_pattern_with_settings(
                encrypted_part, key, iv, crypt_byte_block, skip_byte_block
            )
            result.extend(decrypted)
            offset += encrypted_bytes

        # If there's any remaining data after subsamples, copy as-is
        if offset < len(sample):
            result.extend(sample[offset:])

        return result

    def _decrypt_cbcs_pattern_with_settings(
        self, data: bytes, key: bytes, iv: bytes, crypt_blocks: int, skip_blocks: int
    ) -> bytes:
        """
        Decrypts data using CBCS pattern encryption with explicit pattern settings.

        Args:
            data (bytes): The encrypted data.
            key (bytes): The decryption key.
            iv (bytes): The initialization vector.
            crypt_blocks (int): Number of encrypted blocks in pattern.
            skip_blocks (int): Number of clear blocks in pattern.

        Returns:
            bytes: The decrypted data.
        """
        if not data:
            return data

        block_size = 16

        # If both crypt=0 and skip=0, it means full sample CBC encryption (no pattern)
        # This is common for audio tracks in CBCS
        if crypt_blocks == 0 and skip_blocks == 0:
            # Decrypt complete blocks only
            complete_blocks_size = (len(data) // block_size) * block_size
            if complete_blocks_size > 0:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = cipher.decrypt(data[:complete_blocks_size])
                if complete_blocks_size < len(data):
                    return decrypted + data[complete_blocks_size:]
                return decrypted
            return data

        crypt_bytes = crypt_blocks * block_size
        skip_bytes = skip_blocks * block_size

        # Step 1: Collect all encrypted blocks
        encrypted_blocks = bytearray()
        block_positions = []  # Track where each encrypted block came from
        pos = 0

        while pos < len(data):
            # Encrypted portion
            if pos + crypt_bytes <= len(data):
                encrypted_blocks.extend(data[pos : pos + crypt_bytes])
                block_positions.append((pos, crypt_bytes))
                pos += crypt_bytes
            else:
                # Remaining data - encrypt complete blocks only
                remaining = len(data) - pos
                complete = (remaining // block_size) * block_size
                if complete > 0:
                    encrypted_blocks.extend(data[pos : pos + complete])
                    block_positions.append((pos, complete))
                    pos += complete
                break

            # Skip clear portion
            if pos + skip_bytes <= len(data):
                pos += skip_bytes
            else:
                break

        # Step 2: Decrypt all encrypted blocks as a continuous CBC stream
        if encrypted_blocks:
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_blocks = cipher.decrypt(bytes(encrypted_blocks))
        else:
            decrypted_blocks = b""

        # Step 3: Reconstruct the output with decrypted blocks and clear blocks
        result = bytearray(data)  # Start with original data
        decrypted_pos = 0

        for orig_pos, length in block_positions:
            result[orig_pos : orig_pos + length] = decrypted_blocks[decrypted_pos : decrypted_pos + length]
            decrypted_pos += length

        return bytes(result)

    def _process_trun(self, trun: MP4Atom) -> tuple[int, int]:
        """
        Processes the 'trun' (Track Fragment Run) atom, which contains information about the samples in a track fragment.
        This includes sample sizes, durations, flags, and composition time offsets.

        Args:
            trun (MP4Atom): The 'trun' atom to process.

        Returns:
            tuple[int, int]: (sample_count, data_offset_value) where data_offset_value is the offset
                             into mdat where this track's samples start (0 if not present in trun).
        """
        trun_flags, sample_count = struct.unpack_from(">II", trun.data, 0)
        parse_offset = 8

        # Extract data_offset if present (flag 0x000001)
        trun_data_offset = 0
        if trun_flags & 0x000001:
            trun_data_offset = struct.unpack_from(">i", trun.data, parse_offset)[0]  # signed int
            parse_offset += 4
        if trun_flags & 0x000004:  # first-sample-flags-present
            parse_offset += 4

        self.trun_sample_sizes = array.array("I")

        for _ in range(sample_count):
            if trun_flags & 0x000100:  # sample-duration-present flag
                parse_offset += 4
            if trun_flags & 0x000200:  # sample-size-present flag
                sample_size = struct.unpack_from(">I", trun.data, parse_offset)[0]
                self.trun_sample_sizes.append(sample_size)
                parse_offset += 4
            else:
                self.trun_sample_sizes.append(0)  # Using 0 instead of None for uniformity in the array
            if trun_flags & 0x000400:  # sample-flags-present flag
                parse_offset += 4
            if trun_flags & 0x000800:  # sample-composition-time-offsets-present flag
                parse_offset += 4

        return sample_count, trun_data_offset

    def _modify_trun(self, trun: MP4Atom) -> MP4Atom:
        """
        Modifies the 'trun' (Track Fragment Run) atom to update the data offset.
        This is necessary to account for the total encryption overhead from all trafs,
        since mdat comes after all trafs in the moof.

        Args:
            trun (MP4Atom): The 'trun' atom to modify.

        Returns:
            MP4Atom: Modified 'trun' atom with updated data offset.
        """
        trun_data = bytearray(trun.data)
        current_flags = struct.unpack_from(">I", trun_data, 0)[0] & 0xFFFFFF

        # If the data-offset-present flag is set, update the data offset to account for encryption overhead
        # All trun data_offsets need to be reduced by the total encryption overhead from all trafs
        if current_flags & 0x000001:
            current_data_offset = struct.unpack_from(">i", trun_data, 8)[0]
            struct.pack_into(">i", trun_data, 8, current_data_offset - self.total_encryption_overhead)

        return MP4Atom(b"trun", len(trun_data) + 8, trun_data)

    def _process_sidx(self, sidx: MP4Atom) -> MP4Atom:
        """
        Processes the 'sidx' (Segment Index) atom, which contains indexing information for media segments.
        This includes references to media segments and their durations.

        Args:
            sidx (MP4Atom): The 'sidx' atom to process.

        Returns:
            MP4Atom: Processed 'sidx' atom with updated segment references.
        """
        sidx_data = bytearray(sidx.data)

        current_size = struct.unpack_from(">I", sidx_data, 32)[0]
        reference_type = current_size >> 31
        current_referenced_size = current_size & 0x7FFFFFFF

        # Remove total encryption overhead from referenced size
        new_referenced_size = current_referenced_size - self.total_encryption_overhead
        new_size = (reference_type << 31) | new_referenced_size
        struct.pack_into(">I", sidx_data, 32, new_size)

        return MP4Atom(b"sidx", len(sidx_data) + 8, sidx_data)

    def _process_trak(self, trak: MP4Atom) -> MP4Atom:
        """
        Processes the 'trak' (Track) atom, which contains information about a single track in the movie.
        This includes track header, media information, and other track-level metadata.

        Args:
            trak (MP4Atom): The 'trak' atom to process.

        Returns:
            MP4Atom: Processed 'trak' atom with updated track information.
        """
        parser = MP4Parser(trak.data)
        new_trak_data = bytearray()

        # First pass: find track ID from tkhd
        for atom in parser.list_atoms():
            if atom.atom_type == b"tkhd":
                # tkhd: version(1) + flags(3) + ... + track_id at offset 12 (v0) or 20 (v1)
                version = atom.data[0]
                if version == 0:
                    self.current_track_id = struct.unpack_from(">I", atom.data, 12)[0]
                else:
                    self.current_track_id = struct.unpack_from(">I", atom.data, 20)[0]
                break

        # Second pass: process atoms
        parser.position = 0
        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"mdia":
                new_mdia = self._process_mdia(atom)
                new_trak_data.extend(new_mdia.pack())
            else:
                new_trak_data.extend(atom.pack())

        return MP4Atom(b"trak", len(new_trak_data) + 8, new_trak_data)

    def _process_mdia(self, mdia: MP4Atom) -> MP4Atom:
        """
        Processes the 'mdia' (Media) atom, which contains media information for a track.
        This includes media header, handler reference, and media information container.

        Args:
            mdia (MP4Atom): The 'mdia' atom to process.

        Returns:
            MP4Atom: Processed 'mdia' atom with updated media information.
        """
        parser = MP4Parser(mdia.data)
        new_mdia_data = bytearray()

        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"minf":
                new_minf = self._process_minf(atom)
                new_mdia_data.extend(new_minf.pack())
            else:
                new_mdia_data.extend(atom.pack())

        return MP4Atom(b"mdia", len(new_mdia_data) + 8, new_mdia_data)

    def _process_minf(self, minf: MP4Atom) -> MP4Atom:
        """
        Processes the 'minf' (Media Information) atom, which contains information about the media data in a track.
        This includes data information, sample table, and other media-level metadata.

        Args:
            minf (MP4Atom): The 'minf' atom to process.

        Returns:
            MP4Atom: Processed 'minf' atom with updated media information.
        """
        parser = MP4Parser(minf.data)
        new_minf_data = bytearray()

        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"stbl":
                new_stbl = self._process_stbl(atom)
                new_minf_data.extend(new_stbl.pack())
            else:
                new_minf_data.extend(atom.pack())

        return MP4Atom(b"minf", len(new_minf_data) + 8, new_minf_data)

    def _process_stbl(self, stbl: MP4Atom) -> MP4Atom:
        """
        Processes the 'stbl' (Sample Table) atom, which contains information about the samples in a track.
        This includes sample descriptions, sample sizes, sample times, and other sample-level metadata.

        Args:
            stbl (MP4Atom): The 'stbl' atom to process.

        Returns:
            MP4Atom: Processed 'stbl' atom with updated sample information.
        """
        parser = MP4Parser(stbl.data)
        new_stbl_data = bytearray()

        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"stsd":
                new_stsd = self._process_stsd(atom)
                new_stbl_data.extend(new_stsd.pack())
            else:
                new_stbl_data.extend(atom.pack())

        return MP4Atom(b"stbl", len(new_stbl_data) + 8, new_stbl_data)

    def _process_stsd(self, stsd: MP4Atom) -> MP4Atom:
        """
        Processes the 'stsd' (Sample Description) atom, which contains descriptions of the sample entries in a track.
        This includes codec information, sample entry details, and other sample description metadata.

        Args:
            stsd (MP4Atom): The 'stsd' atom to process.

        Returns:
            MP4Atom: Processed 'stsd' atom with updated sample descriptions.
        """
        parser = MP4Parser(stsd.data)
        entry_count = struct.unpack_from(">I", parser.data, 4)[0]
        new_stsd_data = bytearray(stsd.data[:8])

        parser.position = 8  # Move past version_flags and entry_count

        for _ in range(entry_count):
            sample_entry = parser.read_atom()
            if not sample_entry:
                break

            processed_entry = self._process_sample_entry(sample_entry)
            new_stsd_data.extend(processed_entry.pack())

        return MP4Atom(b"stsd", len(new_stsd_data) + 8, new_stsd_data)

    def _process_sample_entry(self, entry: MP4Atom) -> MP4Atom:
        """
        Processes a sample entry atom, which contains information about a specific type of sample.
        This includes codec-specific information and other sample entry details.

        Args:
            entry (MP4Atom): The sample entry atom to process.

        Returns:
            MP4Atom: Processed sample entry atom with updated information.
        """
        # Determine the size of fixed fields based on sample entry type
        if entry.atom_type in {b"mp4a", b"enca"}:
            fixed_size = 28  # 8 bytes for size, type and reserved, 20 bytes for fixed fields in Audio Sample Entry.
        elif entry.atom_type in {b"mp4v", b"encv", b"avc1", b"hev1", b"hvc1"}:
            fixed_size = 78  # 8 bytes for size, type and reserved, 70 bytes for fixed fields in Video Sample Entry.
        else:
            fixed_size = 16  # 8 bytes for size, type and reserved, 8 bytes for fixed fields in other Sample Entries.

        new_entry_data = bytearray(entry.data[:fixed_size])
        parser = MP4Parser(entry.data[fixed_size:])
        codec_format = None

        for atom in iter(parser.read_atom, None):
            if atom.atom_type in {b"sinf", b"schi", b"tenc", b"schm"}:
                if atom.atom_type == b"sinf":
                    codec_format = self._extract_codec_format(atom)
                continue  # Skip encryption-related atoms
            new_entry_data.extend(atom.pack())

        # Replace the atom type with the extracted codec format
        new_type = codec_format if codec_format else entry.atom_type
        return MP4Atom(new_type, len(new_entry_data) + 8, new_entry_data)

    def _extract_codec_format(self, sinf: MP4Atom) -> Optional[bytes]:
        """
        Extracts the codec format from the 'sinf' (Protection Scheme Information) atom.
        This includes information about the original format of the protected content.
        Also extracts IV size from the 'tenc' box and encryption scheme from 'schm' box.

        Args:
            sinf (MP4Atom): The 'sinf' atom to extract from.

        Returns:
            Optional[bytes]: The codec format or None if not found.
        """
        parser = MP4Parser(sinf.data)
        codec_format = None
        for atom in iter(parser.read_atom, None):
            if atom.atom_type == b"frma":
                codec_format = atom.data
            elif atom.atom_type == b"schm":
                self._parse_schm(atom)
            elif atom.atom_type == b"schi":
                # Parse schi to find tenc
                schi_parser = MP4Parser(atom.data)
                for schi_atom in iter(schi_parser.read_atom, None):
                    if schi_atom.atom_type == b"tenc":
                        self._parse_tenc(schi_atom)
        return codec_format

    def _parse_schm(self, schm: MP4Atom) -> None:
        """
        Parses the 'schm' (Scheme Type) atom to detect the encryption scheme.

        Args:
            schm (MP4Atom): The 'schm' atom to parse.
        """
        # schm structure:
        # - version (1 byte) + flags (3 bytes) = 4 bytes
        # - scheme_type (4 bytes): "cenc", "cens", "cbc1", or "cbcs"
        # - scheme_version (4 bytes)
        data = schm.data
        if len(data) >= 8:
            scheme_type = bytes(data[4:8])
            if scheme_type in (b"cenc", b"cens", b"cbc1", b"cbcs"):
                self.encryption_scheme = scheme_type

    def _parse_tenc(self, tenc: MP4Atom) -> None:
        """
        Parses the 'tenc' (Track Encryption) atom to extract encryption parameters.
        Stores per-track encryption settings for multi-track support.

        Args:
            tenc (MP4Atom): The 'tenc' atom to parse.
        """
        # tenc structure:
        # - version (1 byte) + flags (3 bytes) = 4 bytes
        # - reserved (1 byte) + reserved (1 byte) if version == 0, or reserved (1 byte) + default_crypt_byte_block (4 bits) + default_skip_byte_block (4 bits) if version > 0
        # - default_isProtected (1 byte)
        # - default_Per_Sample_IV_Size (1 byte)
        # - default_KID (16 bytes)
        # For version 1 with IV size 0:
        # - default_constant_IV_size (1 byte)
        # - default_constant_IV (default_constant_IV_size bytes)
        data = tenc.data
        if len(data) >= 8:
            version = data[0]

            # Initialize per-track settings
            track_settings = {
                "crypt_byte_block": 1,  # Default
                "skip_byte_block": 9,  # Default
                "constant_iv": None,
                "iv_size": 8,
                "kid": None,  # KID from tenc box
            }

            # Extract pattern encryption parameters for version > 0 (used in cbcs)
            if version > 0 and len(data) >= 6:
                # Byte 5 contains crypt_byte_block (upper 4 bits) and skip_byte_block (lower 4 bits)
                pattern_byte = data[5]
                track_settings["crypt_byte_block"] = (pattern_byte >> 4) & 0x0F
                track_settings["skip_byte_block"] = pattern_byte & 0x0F
                # Also update global defaults (for backward compatibility)
                self.crypt_byte_block = track_settings["crypt_byte_block"]
                self.skip_byte_block = track_settings["skip_byte_block"]

            # Extract KID (default_KID is at offset 8, 16 bytes)
            kid_offset = 8
            if len(data) >= kid_offset + 16:
                kid = bytes(data[kid_offset : kid_offset + 16])
                track_settings["kid"] = kid
                # Also store globally for backward compatibility
                if not hasattr(self, "extracted_kids"):
                    self.extracted_kids = {}
                if self.current_track_id > 0:
                    self.extracted_kids[self.current_track_id] = kid

            # IV size is at offset 7 for both versions
            iv_size_offset = 7
            if len(data) > iv_size_offset:
                iv_size = data[iv_size_offset]
                if iv_size in (0, 8, 16):
                    # IV size of 0 means constant IV (used in cbcs)
                    track_settings["iv_size"] = iv_size if iv_size > 0 else 16
                    self.default_iv_size = track_settings["iv_size"]

                    # If IV size is 0, extract constant IV from tenc (for CBCS)
                    if iv_size == 0:
                        # After KID (16 bytes at offset 8), there's constant_IV_size (1 byte) and constant_IV
                        constant_iv_size_offset = 8 + 16  # offset 24
                        if len(data) > constant_iv_size_offset:
                            constant_iv_size = data[constant_iv_size_offset]
                            constant_iv_offset = constant_iv_size_offset + 1
                            if constant_iv_size > 0 and len(data) >= constant_iv_offset + constant_iv_size:
                                track_settings["constant_iv"] = bytes(
                                    data[constant_iv_offset : constant_iv_offset + constant_iv_size]
                                )
                                self.constant_iv = track_settings["constant_iv"]

            # Store per-track settings
            if self.current_track_id > 0:
                self.track_encryption_settings[self.current_track_id] = track_settings


def decrypt_segment(
    init_segment: bytes, segment_content: bytes, key_id: str, key: str, include_init: bool = True
) -> bytes:
    """
    Decrypts a CENC encrypted MP4 segment.

    Args:
        init_segment (bytes): Initialization segment data.
        segment_content (bytes): Encrypted segment content.
        key_id (str): Key ID in hexadecimal format.
        key (str): Key in hexadecimal format.
        include_init (bool): If True, include processed init segment in output.
            If False, only return decrypted media segment (for use with EXT-X-MAP).

    Returns:
        bytes: Decrypted segment with processed init (moov/ftyp) + decrypted media (moof/mdat),
            or just decrypted media if include_init is False.
    """
    key_map = {bytes.fromhex(key_id): bytes.fromhex(key)}
    decrypter = MP4Decrypter(key_map)
    decrypted_content = decrypter.decrypt_segment(init_segment + segment_content, include_init=include_init)
    return decrypted_content


def process_drm_init_segment(init_segment: bytes, key_id: str, key: str) -> bytes:
    """
    Processes a DRM-protected init segment for use with EXT-X-MAP.
    Removes encryption-related boxes but keeps the moov structure.

    Args:
        init_segment (bytes): Initialization segment data.
        key_id (str): Key ID in hexadecimal format.
        key (str): Key in hexadecimal format.

    Returns:
        bytes: Processed init segment with encryption boxes removed.
    """
    key_map = {bytes.fromhex(key_id): bytes.fromhex(key)}
    decrypter = MP4Decrypter(key_map)
    processed_init = decrypter.process_init_only(init_segment)
    return processed_init


def cli():
    """
    Command line interface for decrypting a CENC encrypted MP4 segment.
    """
    init_segment = b""

    if args.init and args.segment:
        with open(args.init, "rb") as f:
            init_segment = f.read()
        with open(args.segment, "rb") as f:
            segment_content = f.read()
    elif args.combined_segment:
        with open(args.combined_segment, "rb") as f:
            segment_content = f.read()
    else:
        print("Usage: python mp4decrypt.py --help")
        sys.exit(1)

    try:
        decrypted_segment = decrypt_segment(init_segment, segment_content, args.key_id, args.key)
        print(f"Decrypted content size is {len(decrypted_segment)} bytes")
        with open(args.output, "wb") as f:
            f.write(decrypted_segment)
        print(f"Decrypted segment written to {args.output}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(description="Decrypts a MP4 init and media segment using CENC encryption.")
    arg_parser.add_argument("--init", help="Path to the init segment file", required=False)
    arg_parser.add_argument("--segment", help="Path to the media segment file", required=False)
    arg_parser.add_argument(
        "--combined_segment", help="Path to the combined init and media segment file", required=False
    )
    arg_parser.add_argument("--key_id", help="Key ID in hexadecimal format", required=True)
    arg_parser.add_argument("--key", help="Key in hexadecimal format", required=True)
    arg_parser.add_argument("--output", help="Path to the output file", required=True)
    args = arg_parser.parse_args()
    cli()
