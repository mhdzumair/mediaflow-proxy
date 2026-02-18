"""
Media remuxer package.

Provides pure Python implementations for media container parsing, remuxing,
and transcoding:

- ebml_parser: Minimal EBML/MKV parser for seeking and demuxing
- ts_muxer: fMP4 -> MPEG-TS remuxer
- mkv_demuxer: Streaming MKV demuxer
- mp4_muxer: MP4 box builder for standard moov-first MP4
- audio_transcoder: PyAV-based audio frame transcoding
- video_transcoder: GPU-accelerated video transcoding via PyAV
- pyav_demuxer: Universal PyAV-based streaming demuxer (any container)
- codec_utils: Codec compatibility detection and decision engine
- media_source: Abstract MediaSource protocol (Telegram, HTTP, etc.)
- transcode_handler: Shared transcode request orchestrator
- transcode_pipeline: MKV fast-path and universal transcode pipelines
"""
