"""
Pure Python MP4 box builder for both standard and fragmented MP4.

Supports two modes:

1. Standard MP4 (moov-first): For progressive download with HTTP Range seeking.
   File layout: ftyp | moov (full sample tables) | mdat

2. Fragmented MP4 (fMP4): For on-the-fly streaming via StreamingResponse.
   Init segment: ftyp | moov (empty_moov with mvex)
   Media segments: moof (tfhd + tfdt + trun) | mdat

The fMP4 mode is used for the transcode pipeline where MKV frames are
demuxed, audio is transcoded, and fMP4 fragments are streamed out
immediately without buffering the entire file.
"""

import logging
import struct
from dataclasses import dataclass, field

from mediaflow_proxy.remuxer.ebml_parser import MKVTrack, CODEC_ID_H264, CODEC_ID_H265

logger = logging.getLogger(__name__)


# =============================================================================
# Sample metadata
# =============================================================================


@dataclass
class SampleEntry:
    """Metadata for a single sample (frame) in the MP4 file."""

    size: int  # Sample size in bytes
    duration: int  # Duration in track timescale ticks
    is_sync: bool  # True for keyframes (video) or all audio samples
    composition_offset: int = 0  # CTS offset (for B-frames)


@dataclass
class TrackSamples:
    """Collected sample metadata for one track during muxing."""

    samples: list[SampleEntry] = field(default_factory=list)
    chunk_offsets: list[int] = field(default_factory=list)  # Absolute byte offset of each chunk in mdat
    total_size: int = 0  # Total bytes of all samples
    total_duration: int = 0  # Total duration in timescale ticks

    def add(self, sample: SampleEntry) -> None:
        self.samples.append(sample)
        self.total_size += sample.size
        self.total_duration += sample.duration


# =============================================================================
# Box building primitives
# =============================================================================


def build_box(box_type: bytes, payload: bytes) -> bytes:
    """Build a standard MP4 box: [4-byte size][4-byte type][payload]."""
    size = 8 + len(payload)
    return struct.pack(">I", size) + box_type + payload


def build_full_box(box_type: bytes, version: int, flags: int, payload: bytes) -> bytes:
    """Build a full box with version and flags."""
    inner = struct.pack(">I", (version << 24) | (flags & 0xFFFFFF)) + payload
    return build_box(box_type, inner)


def build_box_header_large(box_type: bytes, total_size: int) -> bytes:
    """Build a box header for large boxes using 64-bit extended size."""
    # size=1 signals extended size; actual size follows as uint64
    return struct.pack(">I", 1) + box_type + struct.pack(">Q", total_size)


# =============================================================================
# ftyp box
# =============================================================================


def build_ftyp() -> bytes:
    """Build the File Type box for isom/iso2/mp41 compatible MP4."""
    payload = b"isom"  # major brand
    payload += struct.pack(">I", 0x200)  # minor version
    payload += b"isom" + b"iso2" + b"mp41"  # compatible brands
    return build_box(b"ftyp", payload)


# =============================================================================
# moov box and children
# =============================================================================


def build_mvhd(timescale: int, duration: int) -> bytes:
    """Build Movie Header box (mvhd), version 0."""
    payload = bytearray()
    payload.extend(struct.pack(">I", 0))  # creation_time
    payload.extend(struct.pack(">I", 0))  # modification_time
    payload.extend(struct.pack(">I", timescale))
    payload.extend(struct.pack(">I", duration))
    payload.extend(struct.pack(">I", 0x00010000))  # rate = 1.0
    payload.extend(struct.pack(">H", 0x0100))  # volume = 1.0
    payload.extend(b"\x00" * 10)  # reserved
    # Unity matrix (3x3, each 4 bytes, 9 values = 36 bytes)
    payload.extend(struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000))
    payload.extend(b"\x00" * 24)  # pre_defined
    payload.extend(struct.pack(">I", 3))  # next_track_ID (1=video, 2=audio, next=3)
    return build_full_box(b"mvhd", 0, 0, bytes(payload))


def build_tkhd(track_id: int, duration: int, width: int = 0, height: int = 0, is_audio: bool = False) -> bytes:
    """Build Track Header box (tkhd), version 0."""
    flags = 0x000003  # track_enabled | track_in_movie
    payload = bytearray()
    payload.extend(struct.pack(">I", 0))  # creation_time
    payload.extend(struct.pack(">I", 0))  # modification_time
    payload.extend(struct.pack(">I", track_id))
    payload.extend(b"\x00" * 4)  # reserved
    payload.extend(struct.pack(">I", duration))
    payload.extend(b"\x00" * 8)  # reserved
    payload.extend(struct.pack(">H", 0))  # layer
    payload.extend(struct.pack(">H", 0 if not is_audio else 1))  # alternate_group
    payload.extend(struct.pack(">H", 0x0100 if is_audio else 0))  # volume
    payload.extend(b"\x00" * 2)  # reserved
    # Unity matrix
    payload.extend(struct.pack(">9I", 0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000))
    # Width and height as 16.16 fixed-point
    payload.extend(struct.pack(">I", width << 16))
    payload.extend(struct.pack(">I", height << 16))
    return build_full_box(b"tkhd", 0, flags, bytes(payload))


def build_mdhd(timescale: int, duration: int) -> bytes:
    """Build Media Header box (mdhd), version 0."""
    payload = bytearray()
    payload.extend(struct.pack(">I", 0))  # creation_time
    payload.extend(struct.pack(">I", 0))  # modification_time
    payload.extend(struct.pack(">I", timescale))
    payload.extend(struct.pack(">I", duration))
    payload.extend(struct.pack(">H", 0x55C4))  # language: 'und'
    payload.extend(struct.pack(">H", 0))  # pre_defined
    return build_full_box(b"mdhd", 0, 0, bytes(payload))


def build_hdlr(handler_type: bytes, name: str) -> bytes:
    """Build Handler Reference box (hdlr)."""
    payload = bytearray()
    payload.extend(b"\x00" * 4)  # pre_defined
    payload.extend(handler_type)  # handler_type (4 bytes)
    payload.extend(b"\x00" * 12)  # reserved
    payload.extend(name.encode("utf-8") + b"\x00")
    return build_full_box(b"hdlr", 0, 0, bytes(payload))


def build_vmhd() -> bytes:
    """Build Video Media Header box (vmhd)."""
    payload = struct.pack(">H", 0)  # graphicsmode
    payload += struct.pack(">3H", 0, 0, 0)  # opcolor
    return build_full_box(b"vmhd", 0, 1, payload)  # flags=1


def build_smhd() -> bytes:
    """Build Sound Media Header box (smhd)."""
    payload = struct.pack(">H", 0)  # balance
    payload += b"\x00\x00"  # reserved
    return build_full_box(b"smhd", 0, 0, payload)


def build_dref() -> bytes:
    """Build Data Reference box (dref) with a self-contained URL entry."""
    url_box = build_full_box(b"url ", 0, 1, b"")  # flags=1 = self-contained
    payload = struct.pack(">I", 1) + url_box  # entry_count=1
    return build_full_box(b"dref", 0, 0, payload)


def build_dinf() -> bytes:
    """Build Data Information box (dinf)."""
    return build_box(b"dinf", build_dref())


# =============================================================================
# Sample table boxes (stbl)
# =============================================================================


def build_stsd_video(track: MKVTrack) -> bytes:
    """Build Sample Description box (stsd) for a video track."""
    # Build the codec-specific sample entry
    if track.codec_id == CODEC_ID_H264:
        entry = _build_avc1_entry(track)
    elif track.codec_id == CODEC_ID_H265:
        entry = _build_hvc1_entry(track)
    else:
        raise ValueError(f"Unsupported video codec: {track.codec_id}")

    payload = struct.pack(">I", 1) + entry  # entry_count=1
    return build_full_box(b"stsd", 0, 0, payload)


def _build_colr_nclx(
    colour_primaries: int = 1,
    transfer_characteristics: int = 1,
    matrix_coefficients: int = 1,
    full_range: bool = False,
) -> bytes:
    """
    Build a colr box with nclx (video colour) information.

    Defaults to BT.709 (the standard for HD content), matching ffmpeg's
    default behaviour for fMP4 output.
    """
    payload = b"nclx"
    payload += struct.pack(">HHH", colour_primaries, transfer_characteristics, matrix_coefficients)
    payload += struct.pack("B", 0x80 if full_range else 0x00)
    return build_box(b"colr", payload)


def _build_pasp(h_spacing: int = 1, v_spacing: int = 1) -> bytes:
    """
    Build a pasp (Pixel Aspect Ratio) box.

    Default 1:1 (square pixels), which is the norm for HD content.
    """
    return build_box(b"pasp", struct.pack(">II", h_spacing, v_spacing))


def _build_avc1_entry(track: MKVTrack) -> bytes:
    """Build an avc3 VisualSampleEntry.

    Uses ``avc3`` instead of ``avc1`` to allow in-band SPS/PPS parameter
    set updates in sample data.  Many MKV sources embed mid-stream PPS
    changes in the bitstream; ``avc3`` signals to the player that these
    may appear in any sample, avoiding "non-existing PPS" decode errors.
    """
    payload = bytearray()
    payload.extend(b"\x00" * 6)  # reserved
    payload.extend(struct.pack(">H", 1))  # data_reference_index
    payload.extend(b"\x00" * 16)  # pre_defined + reserved
    payload.extend(struct.pack(">H", track.pixel_width))
    payload.extend(struct.pack(">H", track.pixel_height))
    payload.extend(struct.pack(">I", 0x00480000))  # horizresolution 72 dpi
    payload.extend(struct.pack(">I", 0x00480000))  # vertresolution 72 dpi
    payload.extend(b"\x00" * 4)  # reserved
    payload.extend(struct.pack(">H", 1))  # frame_count
    payload.extend(b"\x00" * 32)  # compressorname
    payload.extend(struct.pack(">H", 0x0018))  # depth = 24
    payload.extend(struct.pack(">h", -1))  # pre_defined

    # avcC box from CodecPrivate
    if track.codec_private:
        avcc = build_box(b"avcC", track.codec_private)
        payload.extend(avcc)

    # colr box -- nclx colour information (BT.709)
    payload.extend(_build_colr_nclx())
    # pasp box -- pixel aspect ratio (1:1)
    payload.extend(_build_pasp())

    return build_box(b"avc3", bytes(payload))


def _build_hvc1_entry(track: MKVTrack) -> bytes:
    """Build an hvc1 VisualSampleEntry."""
    payload = bytearray()
    payload.extend(b"\x00" * 6)  # reserved
    payload.extend(struct.pack(">H", 1))  # data_reference_index
    payload.extend(b"\x00" * 16)  # pre_defined + reserved
    payload.extend(struct.pack(">H", track.pixel_width))
    payload.extend(struct.pack(">H", track.pixel_height))
    payload.extend(struct.pack(">I", 0x00480000))  # horizresolution
    payload.extend(struct.pack(">I", 0x00480000))  # vertresolution
    payload.extend(b"\x00" * 4)  # reserved
    payload.extend(struct.pack(">H", 1))  # frame_count
    payload.extend(b"\x00" * 32)  # compressorname
    payload.extend(struct.pack(">H", 0x0018))  # depth
    payload.extend(struct.pack(">h", -1))  # pre_defined

    # hvcC box from CodecPrivate
    if track.codec_private:
        hvcc = build_box(b"hvcC", track.codec_private)
        payload.extend(hvcc)

    # colr box -- nclx colour information (BT.709)
    payload.extend(_build_colr_nclx())
    # pasp box -- pixel aspect ratio (1:1)
    payload.extend(_build_pasp())

    return build_box(b"hvc1", bytes(payload))


def build_stsd_audio(sample_rate: int, channels: int, audio_specific_config: bytes) -> bytes:
    """Build Sample Description box (stsd) for an AAC audio track."""
    entry = _build_mp4a_entry(sample_rate, channels, audio_specific_config)
    payload = struct.pack(">I", 1) + entry  # entry_count=1
    return build_full_box(b"stsd", 0, 0, payload)


def _build_mp4a_entry(sample_rate: int, channels: int, asc: bytes) -> bytes:
    """Build an mp4a AudioSampleEntry with esds box."""
    payload = bytearray()
    payload.extend(b"\x00" * 6)  # reserved
    payload.extend(struct.pack(">H", 1))  # data_reference_index
    payload.extend(b"\x00" * 8)  # reserved
    payload.extend(struct.pack(">H", channels))
    payload.extend(struct.pack(">H", 16))  # sample_size (16-bit)
    payload.extend(b"\x00" * 4)  # pre_defined + reserved
    payload.extend(struct.pack(">I", sample_rate << 16))  # sample_rate 16.16

    # esds box
    esds = _build_esds(sample_rate, channels, asc)
    payload.extend(esds)

    return build_box(b"mp4a", bytes(payload))


def _build_esds(sample_rate: int, channels: int, asc: bytes) -> bytes:
    """Build an Elementary Stream Descriptor box (esds) for AAC."""
    # ES_Descriptor
    es_desc = bytearray()
    es_desc.extend(struct.pack(">H", 1))  # ES_ID
    es_desc.append(0x00)  # stream priority

    # DecoderConfigDescriptor
    dec_config = bytearray()
    dec_config.append(0x40)  # objectTypeIndication = Audio ISO/IEC 14496-3 (AAC)
    dec_config.append(0x15)  # streamType=5 (audio) upstream=0 reserved=1
    dec_config.extend(b"\x00\x00\x00")  # bufferSizeDB (3 bytes)
    dec_config.extend(struct.pack(">I", 192000))  # maxBitrate
    dec_config.extend(struct.pack(">I", 192000))  # avgBitrate

    # DecoderSpecificInfo (AudioSpecificConfig)
    dec_specific = _build_descriptor(0x05, asc)
    dec_config.extend(dec_specific)

    dec_config_desc = _build_descriptor(0x04, bytes(dec_config))
    es_desc.extend(dec_config_desc)

    # SLConfigDescriptor (predefined=2 for MP4)
    sl_config = _build_descriptor(0x06, b"\x02")
    es_desc.extend(sl_config)

    es_descriptor = _build_descriptor(0x03, bytes(es_desc))
    payload = es_descriptor
    return build_full_box(b"esds", 0, 0, payload)


def _build_descriptor(tag: int, data: bytes) -> bytes:
    """Build an ISO 14496-1 descriptor with expandable length encoding."""
    length = len(data)
    result = bytearray()
    result.append(tag)

    # Expandable length: use 4 bytes (most compatible)
    result.append(0x80 | ((length >> 21) & 0x7F))
    result.append(0x80 | ((length >> 14) & 0x7F))
    result.append(0x80 | ((length >> 7) & 0x7F))
    result.append(length & 0x7F)

    result.extend(data)
    return bytes(result)


def build_stts(samples: list[SampleEntry]) -> bytes:
    """
    Build Time-to-Sample box (stts) with run-length encoding.

    Groups consecutive samples with the same duration.
    """
    if not samples:
        return build_full_box(b"stts", 0, 0, struct.pack(">I", 0))

    # Run-length encode durations
    entries = []
    current_duration = samples[0].duration
    current_count = 1

    for s in samples[1:]:
        if s.duration == current_duration:
            current_count += 1
        else:
            entries.append((current_count, current_duration))
            current_duration = s.duration
            current_count = 1
    entries.append((current_count, current_duration))

    payload = bytearray()
    payload.extend(struct.pack(">I", len(entries)))
    for count, delta in entries:
        payload.extend(struct.pack(">II", count, delta))

    return build_full_box(b"stts", 0, 0, bytes(payload))


def build_stss(samples: list[SampleEntry]) -> bytes | None:
    """
    Build Sync Sample box (stss) listing keyframe indices.

    Returns None if all samples are sync (audio tracks), as stss is
    only needed when not all samples are sync points.
    """
    sync_indices = [i + 1 for i, s in enumerate(samples) if s.is_sync]  # 1-based

    if len(sync_indices) == len(samples):
        return None  # All samples are sync; omit stss

    payload = bytearray()
    payload.extend(struct.pack(">I", len(sync_indices)))
    for idx in sync_indices:
        payload.extend(struct.pack(">I", idx))

    return build_full_box(b"stss", 0, 0, bytes(payload))


def build_ctts(samples: list[SampleEntry]) -> bytes | None:
    """
    Build Composition Time-to-Sample box (ctts) for B-frame offsets.

    Returns None if no samples have composition offsets.
    """
    has_offsets = any(s.composition_offset != 0 for s in samples)
    if not has_offsets:
        return None

    # Run-length encode offsets
    entries = []
    current_offset = samples[0].composition_offset
    current_count = 1

    for s in samples[1:]:
        if s.composition_offset == current_offset:
            current_count += 1
        else:
            entries.append((current_count, current_offset))
            current_offset = s.composition_offset
            current_count = 1
    entries.append((current_count, current_offset))

    payload = bytearray()
    payload.extend(struct.pack(">I", len(entries)))
    for count, offset in entries:
        payload.extend(struct.pack(">II", count, offset))

    return build_full_box(b"ctts", 0, 0, bytes(payload))


def build_stsz(samples: list[SampleEntry]) -> bytes:
    """Build Sample Size box (stsz)."""
    payload = bytearray()

    # Check if all samples are the same size
    if samples:
        first_size = samples[0].size
        all_same = all(s.size == first_size for s in samples)
    else:
        all_same = True
        first_size = 0

    if all_same and samples:
        payload.extend(struct.pack(">I", first_size))  # sample_size (uniform)
        payload.extend(struct.pack(">I", len(samples)))  # sample_count
    else:
        payload.extend(struct.pack(">I", 0))  # sample_size = 0 (variable)
        payload.extend(struct.pack(">I", len(samples)))
        for s in samples:
            payload.extend(struct.pack(">I", s.size))

    return build_full_box(b"stsz", 0, 0, bytes(payload))


def build_stsc(num_chunks: int) -> bytes:
    """
    Build Sample-to-Chunk box (stsc).

    For simplicity, we use one sample per chunk (each sample gets its
    own chunk offset). This is slightly less compact but much simpler
    and fully correct.
    """
    payload = bytearray()
    payload.extend(struct.pack(">I", 1))  # entry_count
    payload.extend(struct.pack(">III", 1, 1, 1))  # first_chunk=1, samples_per_chunk=1, desc_index=1
    return build_full_box(b"stsc", 0, 0, bytes(payload))


def build_stco(offsets: list[int]) -> bytes:
    """Build Chunk Offset box (stco, 32-bit offsets)."""
    payload = bytearray()
    payload.extend(struct.pack(">I", len(offsets)))
    for off in offsets:
        payload.extend(struct.pack(">I", off))
    return build_full_box(b"stco", 0, 0, bytes(payload))


def build_co64(offsets: list[int]) -> bytes:
    """Build Chunk Offset box (co64, 64-bit offsets) for large files."""
    payload = bytearray()
    payload.extend(struct.pack(">I", len(offsets)))
    for off in offsets:
        payload.extend(struct.pack(">Q", off))
    return build_full_box(b"co64", 0, 0, bytes(payload))


# =============================================================================
# Track building (assembles trak box hierarchy)
# =============================================================================


def build_stbl(track_samples: TrackSamples, stsd: bytes) -> bytes:
    """Build the Sample Table box (stbl) for a track."""
    children = bytearray()
    children.extend(stsd)
    children.extend(build_stts(track_samples.samples))

    stss = build_stss(track_samples.samples)
    if stss is not None:
        children.extend(stss)

    ctts = build_ctts(track_samples.samples)
    if ctts is not None:
        children.extend(ctts)

    children.extend(build_stsz(track_samples.samples))
    children.extend(build_stsc(len(track_samples.chunk_offsets)))

    # Use co64 if any offset exceeds 32-bit range
    needs_64 = any(off > 0xFFFFFFFF for off in track_samples.chunk_offsets)
    if needs_64:
        children.extend(build_co64(track_samples.chunk_offsets))
    else:
        children.extend(build_stco(track_samples.chunk_offsets))

    return build_box(b"stbl", bytes(children))


def build_minf(is_audio: bool, stbl: bytes) -> bytes:
    """Build Media Information box (minf)."""
    children = bytearray()
    if is_audio:
        children.extend(build_smhd())
    else:
        children.extend(build_vmhd())
    children.extend(build_dinf())
    children.extend(stbl)
    return build_box(b"minf", bytes(children))


def build_mdia(timescale: int, duration: int, handler_type: bytes, handler_name: str, minf: bytes) -> bytes:
    """Build Media box (mdia)."""
    children = bytearray()
    children.extend(build_mdhd(timescale, duration))
    children.extend(build_hdlr(handler_type, handler_name))
    children.extend(minf)
    return build_box(b"mdia", bytes(children))


def build_video_trak(
    track: MKVTrack,
    track_id: int,
    timescale: int,
    track_samples: TrackSamples,
    movie_timescale: int,
) -> bytes:
    """Build a complete video trak box."""
    duration_in_track = track_samples.total_duration
    # Convert track duration to movie timescale for tkhd
    if timescale > 0:
        duration_in_movie = int(duration_in_track * movie_timescale / timescale)
    else:
        duration_in_movie = 0

    tkhd = build_tkhd(track_id, duration_in_movie, width=track.pixel_width, height=track.pixel_height)
    stsd = build_stsd_video(track)
    stbl = build_stbl(track_samples, stsd)
    minf = build_minf(is_audio=False, stbl=stbl)
    mdia = build_mdia(timescale, duration_in_track, b"vide", "VideoHandler", minf)

    return build_box(b"trak", tkhd + mdia)


def build_audio_trak(
    track_id: int,
    timescale: int,
    track_samples: TrackSamples,
    movie_timescale: int,
    sample_rate: int,
    channels: int,
    audio_specific_config: bytes,
) -> bytes:
    """Build a complete audio trak box."""
    duration_in_track = track_samples.total_duration
    if timescale > 0:
        duration_in_movie = int(duration_in_track * movie_timescale / timescale)
    else:
        duration_in_movie = 0

    tkhd = build_tkhd(track_id, duration_in_movie, is_audio=True)
    stsd = build_stsd_audio(sample_rate, channels, audio_specific_config)
    stbl = build_stbl(track_samples, stsd)
    minf = build_minf(is_audio=True, stbl=stbl)
    mdia = build_mdia(timescale, duration_in_track, b"soun", "SoundHandler", minf)

    return build_box(b"trak", tkhd + mdia)


# =============================================================================
# Complete moov builder
# =============================================================================


def build_moov(
    video_track: MKVTrack,
    audio_track_info: dict,
    video_samples: TrackSamples,
    audio_samples: TrackSamples,
    mdat_offset: int,
    video_timescale: int = 90000,
    audio_timescale: int = 48000,
    movie_timescale: int = 1000,
) -> bytes:
    """
    Build the complete moov box with all track metadata.

    Args:
        video_track: MKVTrack with video codec info.
        audio_track_info: Dict with keys: sample_rate, channels, audio_specific_config.
        video_samples: Collected video sample metadata.
        audio_samples: Collected audio sample metadata.
        mdat_offset: Byte offset where mdat data starts (after ftyp + moov + mdat header).
        video_timescale: Video track timescale (default 90000 for 90kHz).
        audio_timescale: Audio track timescale (typically sample_rate).
        movie_timescale: Movie header timescale (default 1000 = ms).

    Returns:
        Complete moov box bytes.
    """
    # Calculate movie duration
    video_dur_movie = 0
    if video_timescale > 0 and video_samples.total_duration > 0:
        video_dur_movie = int(video_samples.total_duration * movie_timescale / video_timescale)

    audio_dur_movie = 0
    if audio_timescale > 0 and audio_samples.total_duration > 0:
        audio_dur_movie = int(audio_samples.total_duration * movie_timescale / audio_timescale)

    movie_duration = max(video_dur_movie, audio_dur_movie)

    # Build moov children
    children = bytearray()
    children.extend(build_mvhd(movie_timescale, movie_duration))

    children.extend(
        build_video_trak(
            video_track,
            track_id=1,
            timescale=video_timescale,
            track_samples=video_samples,
            movie_timescale=movie_timescale,
        )
    )

    children.extend(
        build_audio_trak(
            track_id=2,
            timescale=audio_timescale,
            track_samples=audio_samples,
            movie_timescale=movie_timescale,
            sample_rate=audio_track_info["sample_rate"],
            channels=audio_track_info["channels"],
            audio_specific_config=audio_track_info["audio_specific_config"],
        )
    )

    return build_box(b"moov", bytes(children))


# =============================================================================
# mdat box header
# =============================================================================


def build_mdat_header(data_size: int) -> bytes:
    """
    Build the mdat box header.

    Uses extended (64-bit) size if data_size + header > 4GB.
    """
    total = 8 + data_size  # header(8) + data
    if total <= 0xFFFFFFFF:
        return struct.pack(">I", total) + b"mdat"
    # Extended size: size field = 1, then 8-byte actual size
    total_ext = 16 + data_size  # header(16) + data
    return struct.pack(">I", 1) + b"mdat" + struct.pack(">Q", total_ext)


# =============================================================================
# MP4 Builder (high-level orchestrator)
# =============================================================================


class MP4Builder:
    """
    High-level MP4 file builder.

    Collects video and audio samples during a transcode pass, then produces
    a complete moov-first MP4 file.

    Usage:
        builder = MP4Builder(video_track, audio_sample_rate=48000,
                             audio_channels=2, audio_specific_config=asc)
        for frame in video_frames:
            builder.add_video_sample(frame.data, frame.duration_ticks, frame.is_keyframe)
        for frame in audio_frames:
            builder.add_audio_sample(frame.data, frame.duration_ticks)
        moov_bytes, mdat_header, sample_data_list = builder.finalize()
    """

    def __init__(
        self,
        video_track: MKVTrack,
        audio_sample_rate: int = 48000,
        audio_channels: int = 2,
        audio_specific_config: bytes = b"",
        video_timescale: int = 90000,
        audio_timescale: int = 48000,
    ) -> None:
        self._video_track = video_track
        self._audio_info = {
            "sample_rate": audio_sample_rate,
            "channels": audio_channels,
            "audio_specific_config": audio_specific_config,
        }
        self._video_timescale = video_timescale
        self._audio_timescale = audio_timescale

        self._video_samples = TrackSamples()
        self._audio_samples = TrackSamples()
        self._mdat_chunks: list[bytes] = []  # Interleaved sample data
        self._mdat_size: int = 0
        self._sample_order: list[str] = []  # "v" or "a" for each mdat chunk

    def add_video_sample(self, data: bytes, duration_ticks: int, is_keyframe: bool) -> None:
        """Add a video sample (H.264/H.265 NALUs) to the builder."""
        entry = SampleEntry(size=len(data), duration=duration_ticks, is_sync=is_keyframe)
        self._video_samples.add(entry)
        self._mdat_chunks.append(data)
        self._mdat_size += len(data)
        self._sample_order.append("v")

    def add_audio_sample(self, data: bytes, duration_ticks: int) -> None:
        """Add an audio sample (AAC frame) to the builder."""
        entry = SampleEntry(size=len(data), duration=duration_ticks, is_sync=True)
        self._audio_samples.add(entry)
        self._mdat_chunks.append(data)
        self._mdat_size += len(data)
        self._sample_order.append("a")

    @property
    def video_sample_count(self) -> int:
        return len(self._video_samples.samples)

    @property
    def audio_sample_count(self) -> int:
        return len(self._audio_samples.samples)

    @property
    def mdat_size(self) -> int:
        return self._mdat_size

    def finalize(self) -> tuple[bytes, bytes, list[bytes]]:
        """
        Build the final MP4 file components.

        Since moov needs accurate chunk offsets (stco/co64) that depend on
        moov's own size, we do a two-pass approach:
        1. Build moov with placeholder offsets to determine its size
        2. Rebuild moov with correct offsets

        Returns:
            (ftyp_moov_bytes, mdat_header_bytes, mdat_chunk_list)
            Concatenating these gives the complete MP4 file.
        """
        ftyp = build_ftyp()

        # Build mdat header
        mdat_hdr = build_mdat_header(self._mdat_size)

        # Pass 1: Build moov with placeholder (0) offsets to measure its size
        self._compute_chunk_offsets(0)  # Placeholder base
        moov_pass1 = build_moov(
            self._video_track,
            self._audio_info,
            self._video_samples,
            self._audio_samples,
            mdat_offset=0,
            video_timescale=self._video_timescale,
            audio_timescale=self._audio_timescale,
        )

        # Calculate actual mdat data start:
        # ftyp + moov + mdat_header
        mdat_data_start = len(ftyp) + len(moov_pass1) + len(mdat_hdr)

        # Pass 2: Rebuild moov with correct chunk offsets
        self._compute_chunk_offsets(mdat_data_start)
        moov_final = build_moov(
            self._video_track,
            self._audio_info,
            self._video_samples,
            self._audio_samples,
            mdat_offset=mdat_data_start,
            video_timescale=self._video_timescale,
            audio_timescale=self._audio_timescale,
        )

        # Verify moov size didn't change (it shouldn't since offsets are same width)
        if len(moov_final) != len(moov_pass1):
            # Size changed (e.g., offsets crossed 32/64-bit boundary). Redo.
            mdat_data_start = len(ftyp) + len(moov_final) + len(mdat_hdr)
            self._compute_chunk_offsets(mdat_data_start)
            moov_final = build_moov(
                self._video_track,
                self._audio_info,
                self._video_samples,
                self._audio_samples,
                mdat_offset=mdat_data_start,
                video_timescale=self._video_timescale,
                audio_timescale=self._audio_timescale,
            )

        header_bytes = ftyp + moov_final

        logger.info(
            "[mp4_muxer] Finalized: ftyp=%d moov=%d mdat=%d (header=%d) video=%d samples audio=%d samples",
            len(ftyp),
            len(moov_final),
            self._mdat_size,
            len(mdat_hdr),
            len(self._video_samples.samples),
            len(self._audio_samples.samples),
        )

        return header_bytes, mdat_hdr, self._mdat_chunks

    def _compute_chunk_offsets(self, mdat_data_start: int) -> None:
        """Compute absolute byte offsets for each sample in the mdat."""
        # Samples were added interleaved (video/audio/video/audio...)
        # so mdat_chunks[i] corresponds to samples in order.
        # We need to assign offsets per track.
        video_offsets = []
        audio_offsets = []

        offset = mdat_data_start
        vi = 0
        ai = 0

        for chunk in self._mdat_chunks:
            chunk_size = len(chunk)
            # Determine if this chunk is video or audio based on sample order
            if vi < len(self._video_samples.samples) and (
                ai >= len(self._audio_samples.samples) or self._is_video_sample(vi, ai)
            ):
                video_offsets.append(offset)
                vi += 1
            else:
                audio_offsets.append(offset)
                ai += 1
            offset += chunk_size

        self._video_samples.chunk_offsets = video_offsets
        self._audio_samples.chunk_offsets = audio_offsets

    def _is_video_sample(self, vi: int, ai: int) -> bool:
        """
        Determine if the next mdat chunk at position (vi+ai) is a video sample.

        This relies on the add order tracking. We use a simple scheme:
        samples are added in their interleaved order, and we track which
        indices are video vs audio.
        """
        # The _mdat_chunks list contains samples in the order they were added.
        # We need to know the order. For now, use the _sample_order tracker.
        idx = vi + ai
        if idx < len(self._sample_order):
            return self._sample_order[idx] == "v"
        return vi < len(self._video_samples.samples)

    def update_audio_specific_config(self, asc: bytes) -> None:
        """Update the AudioSpecificConfig (e.g., after first encode)."""
        self._audio_info["audio_specific_config"] = asc


# =============================================================================
# Fragmented MP4 (fMP4) builder for streaming output
# =============================================================================
#
# fMP4 layout:
#   Init segment:  ftyp + moov (mvhd + mvex/trex + trak[video] + trak[audio])
#   Media segments: moof (mfhd + traf[tfhd + tfdt + trun]) + mdat
#
# The moov in fMP4 has empty sample tables (stts/stsz/stsc/stco with 0 entries)
# and an mvex box with trex entries signaling fragmented mode.
# =============================================================================


def _build_empty_stbl(stsd: bytes) -> bytes:
    """Build an stbl with empty sample tables (for fMP4 init segment)."""
    children = bytearray()
    children.extend(stsd)
    # Empty stts
    children.extend(build_full_box(b"stts", 0, 0, struct.pack(">I", 0)))
    # Empty stsc
    children.extend(build_full_box(b"stsc", 0, 0, struct.pack(">I", 0)))
    # Empty stsz
    children.extend(build_full_box(b"stsz", 0, 0, struct.pack(">II", 0, 0)))
    # Empty stco
    children.extend(build_full_box(b"stco", 0, 0, struct.pack(">I", 0)))
    return build_box(b"stbl", bytes(children))


def build_fmp4_init_segment(
    video_track: MKVTrack,
    audio_sample_rate: int,
    audio_channels: int,
    audio_specific_config: bytes,
    video_timescale: int = 90000,
    audio_timescale: int = 48000,
    duration_ms: float = 0.0,
) -> bytes:
    """
    Build an fMP4 initialization segment (ftyp + moov with empty_moov).

    The moov contains track descriptions (codec config) and mvex/trex
    entries signaling fragmented mode. No sample data.

    Args:
        video_track: MKVTrack with video codec info.
        audio_sample_rate: Output audio sample rate.
        audio_channels: Output audio channel count.
        audio_specific_config: AAC AudioSpecificConfig bytes.
        video_timescale: Video track timescale (default 90000).
        audio_timescale: Audio track timescale (default sample_rate).
        duration_ms: Total duration in ms (0 = unknown/live).

    Returns:
        Complete init segment bytes (ftyp + moov).
    """
    ftyp = _build_fmp4_ftyp()

    movie_timescale = 1000  # ms
    movie_duration = int(duration_ms) if duration_ms > 0 else 0

    # mvhd
    mvhd = build_mvhd(movie_timescale, movie_duration)

    # Video trak (with empty stbl)
    video_duration = int(duration_ms * video_timescale / 1000.0) if duration_ms > 0 else 0
    video_tkhd = build_tkhd(
        1, int(duration_ms) if duration_ms > 0 else 0, width=video_track.pixel_width, height=video_track.pixel_height
    )
    video_stsd = build_stsd_video(video_track)
    video_stbl = _build_empty_stbl(video_stsd)
    video_minf = build_minf(is_audio=False, stbl=video_stbl)
    video_mdia = build_mdia(video_timescale, video_duration, b"vide", "VideoHandler", video_minf)
    video_trak = build_box(b"trak", video_tkhd + video_mdia)

    # Audio trak (with empty stbl)
    audio_duration = int(duration_ms * audio_timescale / 1000.0) if duration_ms > 0 else 0
    audio_tkhd = build_tkhd(2, int(duration_ms) if duration_ms > 0 else 0, is_audio=True)
    audio_stsd = build_stsd_audio(audio_sample_rate, audio_channels, audio_specific_config)
    audio_stbl = _build_empty_stbl(audio_stsd)
    audio_minf = build_minf(is_audio=True, stbl=audio_stbl)
    audio_mdia = build_mdia(audio_timescale, audio_duration, b"soun", "SoundHandler", audio_minf)
    audio_trak = build_box(b"trak", audio_tkhd + audio_mdia)

    # mvex (Movie Extends) - signals this is a fragmented MP4
    # trex (Track Extends) for each track.
    # Use 0x00000000 for default_sample_flags (same as ffmpeg), deferring
    # all sample flag decisions to per-fragment tfhd.default_sample_flags
    # and trun.first_sample_flags.  This avoids global defaults that could
    # confuse strict browser parsers.
    trex_video = build_full_box(
        b"trex",
        0,
        0,
        struct.pack(
            ">IIIII",
            1,  # track_ID
            1,  # default_sample_description_index
            0,  # default_sample_duration
            0,  # default_sample_size
            0x00000000,  # default_sample_flags (deferred to tfhd per fragment)
        ),
    )
    trex_audio = build_full_box(
        b"trex",
        0,
        0,
        struct.pack(
            ">IIIII",
            2,  # track_ID
            1,  # default_sample_description_index
            0,  # default_sample_duration
            0,  # default_sample_size
            0x00000000,  # default_sample_flags (deferred to tfhd per fragment)
        ),
    )
    mvex = build_box(b"mvex", trex_video + trex_audio)

    # Assemble moov
    moov = build_box(b"moov", mvhd + video_trak + audio_trak + mvex)

    return ftyp + moov


def _build_fmp4_ftyp() -> bytes:
    """Build ftyp box for fragmented MP4."""
    payload = b"isom"  # major brand
    payload += struct.pack(">I", 0x200)  # minor version
    payload += b"isom" + b"iso6" + b"mp41" + b"msdh" + b"msix"
    return build_box(b"ftyp", payload)


@dataclass
class FragmentSample:
    """A single sample to be written into an fMP4 fragment."""

    data: bytes
    duration: int  # In track timescale
    is_sync: bool = False
    composition_offset: int = 0

    @property
    def size(self) -> int:
        return len(self.data)


def build_fmp4_fragment(
    sequence_number: int,
    track_id: int,
    base_decode_time: int,
    samples: list[FragmentSample],
) -> bytes:
    """
    Build an fMP4 media segment (moof + mdat) for a single track.

    Args:
        sequence_number: Fragment sequence number (1-based, incrementing).
        track_id: Track ID (1=video, 2=audio).
        base_decode_time: Decode time of the first sample in track timescale.
        samples: List of samples for this fragment.

    Returns:
        Complete moof + mdat bytes.
    """
    if not samples:
        return b""

    # mdat payload
    mdat_payload = b"".join(s.data for s in samples)

    # Build trun (Track Fragment Run)
    # Flags: 0x000301 = data_offset_present + sample_duration_present + sample_size_present
    # Add 0x000400 if any sample has composition offset
    # Add 0x000004 for first_sample_flags_present
    has_cts = any(s.composition_offset != 0 for s in samples)
    trun_flags = 0x000001 | 0x000100 | 0x000200  # data_offset + duration + size
    if has_cts:
        trun_flags |= 0x000800  # sample_composition_time_offsets_present
    # Use first_sample_flags for keyframe indication
    trun_flags |= 0x000004  # first_sample_flags_present

    trun_payload = bytearray()
    trun_payload.extend(struct.pack(">I", len(samples)))  # sample_count

    # data_offset: will be patched after we know moof size
    # Placeholder for now (4 bytes)
    data_offset_pos = len(trun_payload)
    trun_payload.extend(struct.pack(">i", 0))  # data_offset placeholder

    # first_sample_flags
    if samples[0].is_sync:
        first_flags = 0x02000000  # sample_depends_on=2 (does not depend, i.e., sync)
    else:
        first_flags = 0x01010000  # sample_depends_on=1, is_non_sync=1
    trun_payload.extend(struct.pack(">I", first_flags))

    # Per-sample entries
    for s in samples:
        trun_payload.extend(struct.pack(">I", s.duration))
        trun_payload.extend(struct.pack(">I", s.size))
        if has_cts:
            trun_payload.extend(struct.pack(">i", s.composition_offset))

    # Use version 1 when CTS offsets are present (supports signed offsets for B-frames)
    trun_version = 1 if has_cts else 0
    trun = build_full_box(b"trun", trun_version, trun_flags, bytes(trun_payload))

    # tfdt (Track Fragment Decode Time) - version 1 for 64-bit time
    tfdt_payload = struct.pack(">Q", base_decode_time)
    tfdt = build_full_box(b"tfdt", 1, 0, tfdt_payload)

    # tfhd (Track Fragment Header)
    # Flags: 0x020000 = default_base_is_moof
    #        0x000020 = default_sample_flags_present
    # Since trex.default_sample_flags is 0x00000000, we set per-fragment
    # defaults here (matching ffmpeg behaviour):
    #   - Video: 0x01010000 (sample_depends_on=1, is_non_sync=1)
    #   - Audio: 0x02000000 (sample_depends_on=2 = independent)
    # The trun.first_sample_flags overrides this for keyframes.
    is_video = track_id == 1
    default_sample_flags = 0x01010000 if is_video else 0x02000000
    tfhd_flags = 0x020000 | 0x000020  # default_base_is_moof + default_sample_flags_present
    tfhd_payload = struct.pack(">II", track_id, default_sample_flags)
    tfhd = build_full_box(b"tfhd", 0, tfhd_flags, tfhd_payload)

    # traf
    traf = build_box(b"traf", tfhd + tfdt + trun)

    # mfhd (Movie Fragment Header)
    mfhd = build_full_box(b"mfhd", 0, 0, struct.pack(">I", sequence_number))

    # moof
    moof = build_box(b"moof", mfhd + traf)

    # Patch data_offset in trun: offset from moof start to mdat payload start
    # mdat header is 8 bytes, so data_offset = moof_size + 8
    data_offset = len(moof) + 8  # 8 = mdat box header

    # Find the trun data_offset position within the moof
    # trun is inside traf, which is inside moof.
    # The data_offset is at a fixed position in the trun payload.
    # We need to search for it. Since we built the structure, we can calculate:
    # moof header (8) + mfhd (full box) + traf header (8) + tfhd (full box) + tfdt (full box)
    # + trun header (12 = 8 box + 4 version/flags) + sample_count (4) -> data_offset position
    # Instead of fragile offset math, search for the placeholder pattern.
    # Actually, let's just rebuild with the correct offset.

    # Re-encode trun with correct data_offset
    trun_payload_fixed = bytearray(trun_payload)
    struct.pack_into(">i", trun_payload_fixed, data_offset_pos, data_offset)
    trun_fixed = build_full_box(b"trun", trun_version, trun_flags, bytes(trun_payload_fixed))

    # Rebuild traf -> moof with fixed trun
    traf_fixed = build_box(b"traf", tfhd + tfdt + trun_fixed)
    moof_fixed = build_box(b"moof", mfhd + traf_fixed)

    # Verify size didn't change (it shouldn't)
    assert len(moof_fixed) == len(moof), "moof size changed after data_offset patch"

    # mdat
    mdat = build_box(b"mdat", mdat_payload)

    return bytes(moof_fixed) + mdat


class FMP4StreamMuxer:
    """
    Streaming fMP4 muxer that produces fragments on-the-fly.

    Usage:
        muxer = FMP4StreamMuxer(video_track, audio_sample_rate, ...)
        init_seg = muxer.build_init_segment()
        yield init_seg

        for frame in demuxed_frames:
            muxer.add_frame(frame)
            fragment = muxer.flush_fragment()
            if fragment:
                yield fragment

        final = muxer.flush_final()
        if final:
            yield final
    """

    def __init__(
        self,
        video_track: MKVTrack,
        audio_sample_rate: int = 48000,
        audio_channels: int = 2,
        audio_specific_config: bytes = b"",
        video_timescale: int = 90000,
        audio_timescale: int = 48000,
        duration_ms: float = 0.0,
        fragment_duration_ms: float = 2000.0,
        start_decode_time_ms: float = 0.0,
        audio_frame_size: int = 0,
    ) -> None:
        self._video_track = video_track
        self._audio_sample_rate = audio_sample_rate
        self._audio_channels = audio_channels
        self._audio_specific_config = audio_specific_config
        self._video_timescale = video_timescale
        self._audio_timescale = audio_timescale
        self._duration_ms = duration_ms
        self._fragment_duration_ms = fragment_duration_ms

        # Fragment accumulation
        self._video_samples: list[FragmentSample] = []
        self._audio_samples: list[FragmentSample] = []
        self._sequence_number = 1

        # Track decode times (in timescale ticks).
        # When producing HLS segments, start_decode_time_ms places this
        # segment's tfdt at the correct position in the global timeline.
        self._video_decode_time = int(start_decode_time_ms * video_timescale / 1000.0)

        # For audio, we must align the tfdt to exact frame boundaries to
        # avoid DTS discontinuities at segment borders.  AAC frames are
        # exactly ``audio_frame_size`` samples each (typically 1024).  If
        # the caller provides audio_frame_size, compute the audio base
        # time as the exact number of whole frames that fit before this
        # segment's start time.
        if audio_frame_size > 0 and start_decode_time_ms > 0:
            total_samples_before = start_decode_time_ms / 1000.0 * audio_timescale
            whole_frames_before = int(total_samples_before / audio_frame_size)
            self._audio_decode_time = whole_frames_before * audio_frame_size
        else:
            self._audio_decode_time = int(start_decode_time_ms * audio_timescale / 1000.0)

        # Track accumulated duration for fragment boundary detection
        self._fragment_video_duration = 0  # video ticks accumulated in current fragment
        self._fragment_threshold = int(fragment_duration_ms * video_timescale / 1000.0)

    @property
    def video_position_ticks(self) -> int:
        """Current video decode position (timescale ticks from stream start)."""
        return self._video_decode_time + self._fragment_video_duration

    def advance_video_decode_time(self, ticks: int) -> None:
        """Advance the video base decode time by *ticks*.

        Can be used to adjust the segment's starting decode position when
        the first emitted frame doesn't align with the tfdt origin.
        """
        self._video_decode_time += ticks

    def build_init_segment(self) -> bytes:
        """Build and return the fMP4 init segment (ftyp + moov)."""
        return build_fmp4_init_segment(
            video_track=self._video_track,
            audio_sample_rate=self._audio_sample_rate,
            audio_channels=self._audio_channels,
            audio_specific_config=self._audio_specific_config,
            video_timescale=self._video_timescale,
            audio_timescale=self._audio_timescale,
            duration_ms=self._duration_ms,
        )

    def update_audio_specific_config(self, asc: bytes) -> None:
        """Update the AAC AudioSpecificConfig (call before build_init_segment if possible)."""
        self._audio_specific_config = asc

    def add_video_sample(
        self,
        data: bytes,
        duration_ticks: int,
        is_keyframe: bool,
        pts_ticks: int | None = None,
    ) -> None:
        """
        Add a video sample to the current fragment.

        Args:
            data: Raw video NALUs.
            duration_ticks: Duration in video timescale ticks.
            is_keyframe: Whether this is an IDR/sync sample.
            pts_ticks: Presentation timestamp in video timescale ticks.
                       Used to compute composition_time_offset for B-frame
                       reordering. If None, assumes PTS == DTS (no B-frames).
        """
        # Compute composition_time_offset = PTS - DTS
        # DTS is the running decode time for this fragment
        cts_offset = 0
        if pts_ticks is not None:
            dts = self._video_decode_time + self._fragment_video_duration
            cts_offset = pts_ticks - dts

        self._video_samples.append(
            FragmentSample(
                data=data,
                duration=duration_ticks,
                is_sync=is_keyframe,
                composition_offset=cts_offset,
            )
        )
        self._fragment_video_duration += duration_ticks

    def add_audio_sample(self, data: bytes, duration_ticks: int) -> None:
        """Add an audio sample to the current fragment."""
        self._audio_samples.append(
            FragmentSample(
                data=data,
                duration=duration_ticks,
                is_sync=True,
            )
        )

    def should_flush(self) -> bool:
        """Check if the current fragment has enough data to emit."""
        # Flush on keyframe boundaries after accumulating enough duration
        if self._fragment_video_duration < self._fragment_threshold:
            return False
        # Only flush at a keyframe boundary (if there's a pending keyframe)
        if len(self._video_samples) > 1 and self._video_samples[-1].is_sync:
            return True
        return False

    def flush_fragment(self, force: bool = False) -> bytes | None:
        """
        Flush the current fragment if ready.

        Args:
            force: Force flush even if fragment duration threshold isn't reached.

        Returns:
            Fragment bytes (moof+mdat for video + moof+mdat for audio) or None.
        """
        if not force and not self.should_flush():
            return None

        if not self._video_samples and not self._audio_samples:
            return None

        result = bytearray()

        # When flushing at a keyframe, the last sample (the new keyframe)
        # belongs to the NEXT fragment. Split there.
        if not force and len(self._video_samples) > 1 and self._video_samples[-1].is_sync:
            video_to_emit = self._video_samples[:-1]
            video_remaining = [self._video_samples[-1]]
        else:
            video_to_emit = self._video_samples
            video_remaining = []

        # Emit video fragment
        if video_to_emit:
            frag = build_fmp4_fragment(
                sequence_number=self._sequence_number,
                track_id=1,
                base_decode_time=self._video_decode_time,
                samples=video_to_emit,
            )
            result.extend(frag)
            self._sequence_number += 1

            emitted_duration = sum(s.duration for s in video_to_emit)
            self._video_decode_time += emitted_duration

        # Emit audio fragment (matching time range)
        if self._audio_samples:
            frag = build_fmp4_fragment(
                sequence_number=self._sequence_number,
                track_id=2,
                base_decode_time=self._audio_decode_time,
                samples=self._audio_samples,
            )
            result.extend(frag)
            self._sequence_number += 1

            emitted_audio_duration = sum(s.duration for s in self._audio_samples)
            self._audio_decode_time += emitted_audio_duration
            self._audio_samples = []

        # Reset for next fragment
        self._video_samples = video_remaining
        self._fragment_video_duration = sum(s.duration for s in video_remaining)

        return bytes(result) if result else None

    def flush_final(self) -> bytes | None:
        """Flush any remaining samples as the final fragment."""
        return self.flush_fragment(force=True)
