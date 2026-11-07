from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator


COCOA_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _cocoa_ts(value):
    if value:
        try:
            return COCOA_EPOCH + timedelta(seconds=value)
        except (OSError, OverflowError, ValueError):
            return COCOA_EPOCH
    return COCOA_EPOCH


# ── Record Descriptors ───────────────────────────────────────────────────

KnowledgeCAppUsageRecord = TargetRecordDescriptor(
    "macos/knowledgec/app_usage",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "bundle_id"),
        ("varint", "seconds_from_gmt"),
        ("path", "source"),
    ],
)

KnowledgeCWebUsageRecord = TargetRecordDescriptor(
    "macos/knowledgec/web_usage",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "bundle_id"),
        ("string", "web_url"),
        ("string", "web_domain"),
        ("path", "source"),
    ],
)

KnowledgeCMediaUsageRecord = TargetRecordDescriptor(
    "macos/knowledgec/media_usage",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "bundle_id"),
        ("string", "now_playing_title"),
        ("string", "now_playing_artist"),
        ("string", "now_playing_album"),
        ("string", "now_playing_genre"),
        ("float", "now_playing_duration"),
        ("varint", "now_playing_is_playing"),
        ("path", "source"),
    ],
)

KnowledgeCNotificationRecord = TargetRecordDescriptor(
    "macos/knowledgec/notification",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "bundle_id"),
        ("path", "source"),
    ],
)

KnowledgeCIntentRecord = TargetRecordDescriptor(
    "macos/knowledgec/intent",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "intent_category"),
        ("string", "source_bundle_id"),
        ("string", "intent_class"),
        ("string", "intent_verb"),
        ("varint", "intent_direction"),
        ("varint", "intent_handling_status"),
        ("path", "source"),
    ],
)

KnowledgeCDisplayRecord = TargetRecordDescriptor(
    "macos/knowledgec/display",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("boolean", "is_backlit"),
        ("path", "source"),
    ],
)

KnowledgeCBluetoothRecord = TargetRecordDescriptor(
    "macos/knowledgec/bluetooth",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("boolean", "is_connected"),
        ("string", "device_name"),
        ("string", "device_address"),
        ("varint", "device_type"),
        ("varint", "product_id"),
        ("path", "source"),
    ],
)

KnowledgeCDiscoverabilityRecord = TargetRecordDescriptor(
    "macos/knowledgec/discoverability",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("datetime", "ts_created"),
        ("string", "signal"),
        ("path", "source"),
    ],
)

KnowledgeCSyncPeerRecord = TargetRecordDescriptor(
    "macos/knowledgec/sync_peer",
    [
        ("datetime", "ts_last_seen"),
        ("string", "device_id"),
        ("string", "device_model"),
        ("string", "cloud_id"),
        ("string", "version"),
        ("path", "source"),
    ],
)

KnowledgeCSourceRecord = TargetRecordDescriptor(
    "macos/knowledgec/source",
    [
        ("string", "bundle_id"),
        ("string", "source_id"),
        ("string", "device_id"),
        ("string", "group_id"),
        ("string", "item_id"),
        ("path", "source"),
    ],
)

KnowledgeCHistogramRecord = TargetRecordDescriptor(
    "macos/knowledgec/histogram",
    [
        ("datetime", "ts_start"),
        ("datetime", "ts_end"),
        ("string", "stream_name"),
        ("string", "identifier"),
        ("string", "device_identifier"),
        ("varint", "bucket_id"),
        ("varint", "histogram_id"),
        ("float", "bucket_value"),
        ("path", "source"),
    ],
)

KnowledgeCCustomMetadataRecord = TargetRecordDescriptor(
    "macos/knowledgec/custom_metadata",
    [
        ("string", "name"),
        ("string", "string_value"),
        ("varint", "integer_value"),
        ("float", "double_value"),
        ("datetime", "date_value"),
        ("varint", "object_id"),
        ("path", "source"),
    ],
)


class KnowledgeCPlugin(Plugin):
    """Plugin to parse macOS knowledgeC.db.

    KnowledgeC tracks application usage, web browsing, media, notifications,
    intents, bluetooth connections, display state, and sync peers. It is a
    key artifact for pattern-of-life analysis on macOS.

    Parses the following tables:
    - ZOBJECT (app_usage, web_usage, media_usage, notifications, intents,
      display, bluetooth, discoverability)
    - ZSYNCPEER (sync_peers)
    - ZSOURCE (sources)
    - ZHISTOGRAM + ZHISTOGRAMVALUE (histograms)
    - ZCUSTOMMETADATA (custom_metadata)
    """

    __namespace__ = "knowledgec"

    DB_GLOB = "Users/*/Library/Application Support/Knowledge/knowledgeC.db"

    def __init__(self, target):
        super().__init__(target)
        self._db_paths = list(self.target.fs.path("/").glob(self.DB_GLOB))
        system_path = self.target.fs.path("/private/var/db/CoreDuet/Knowledge/knowledgeC.db")
        if system_path.exists():
            self._db_paths.append(system_path)

    def check_compatible(self) -> None:
        if not self._db_paths:
            raise UnsupportedPluginError("No knowledgeC.db found")

    def _open_db(self, db_path):
        with db_path.open("rb") as fh:
            db_bytes = fh.read()
        tmp = tempfile.NamedTemporaryFile(suffix=".db")  # noqa: SIM115
        tmp.write(db_bytes)
        tmp.flush()

        for suffix in ["-wal", "-shm"]:
            src = db_path.parent.joinpath(db_path.name + suffix)
            if src.exists():
                with src.open("rb") as sf, open(tmp.name + suffix, "wb") as df:  # noqa: PTH123
                    df.write(sf.read())

        conn = sqlite3.connect(tmp.name)
        conn.row_factory = sqlite3.Row
        return conn, tmp

    def _iter_db(self):
        for db_path in self._db_paths:
            try:
                conn, tmp = self._open_db(db_path)
                yield db_path, conn, tmp
            except Exception as e:
                self.target.log.warning("Error opening knowledgeC.db at %s: %s", db_path, e)

    # ── App Usage (/app/usage) ───────────────────────────────────────────

    @export(record=KnowledgeCAppUsageRecord)
    def app_usage(self) -> Iterator[KnowledgeCAppUsageRecord]:
        """Parse application usage events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZVALUESTRING, ZSECONDSFROMGMT
                    FROM ZOBJECT WHERE ZSTREAMNAME = '/app/usage'
                    ORDER BY ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCAppUsageRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        bundle_id=row["ZVALUESTRING"] or "",
                        seconds_from_gmt=row["ZSECONDSFROMGMT"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing app_usage at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Web Usage (/app/webUsage) ────────────────────────────────────────

    @export(record=KnowledgeCWebUsageRecord)
    def web_usage(self) -> Iterator[KnowledgeCWebUsageRecord]:
        """Parse web browsing events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT o.ZSTARTDATE, o.ZENDDATE, o.ZCREATIONDATE, o.ZVALUESTRING,
                           sm.Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN,
                           sm.Z_DKDIGITALHEALTHMETADATAKEY__WEBPAGEURL
                    FROM ZOBJECT o
                    LEFT JOIN ZSTRUCTUREDMETADATA sm ON o.ZSTRUCTUREDMETADATA = sm.Z_PK
                    WHERE o.ZSTREAMNAME = '/app/webUsage'
                    ORDER BY o.ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCWebUsageRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        bundle_id=row["ZVALUESTRING"] or "",
                        web_url=row["Z_DKDIGITALHEALTHMETADATAKEY__WEBPAGEURL"] or "",
                        web_domain=row["Z_DKDIGITALHEALTHMETADATAKEY__WEBDOMAIN"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing web_usage at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Media Usage (/app/mediaUsage) ────────────────────────────────────

    @export(record=KnowledgeCMediaUsageRecord)
    def media_usage(self) -> Iterator[KnowledgeCMediaUsageRecord]:
        """Parse media playback events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT o.ZSTARTDATE, o.ZENDDATE, o.ZCREATIONDATE, o.ZVALUESTRING,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__TITLE,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__ARTIST,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__ALBUM,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__GENRE,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__DURATION,
                           sm.Z_DKNOWPLAYINGMETADATAKEY__PLAYING
                    FROM ZOBJECT o
                    LEFT JOIN ZSTRUCTUREDMETADATA sm ON o.ZSTRUCTUREDMETADATA = sm.Z_PK
                    WHERE o.ZSTREAMNAME = '/app/mediaUsage'
                    ORDER BY o.ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCMediaUsageRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        bundle_id=row["ZVALUESTRING"] or "",
                        now_playing_title=row["Z_DKNOWPLAYINGMETADATAKEY__TITLE"] or "",
                        now_playing_artist=row["Z_DKNOWPLAYINGMETADATAKEY__ARTIST"] or "",
                        now_playing_album=row["Z_DKNOWPLAYINGMETADATAKEY__ALBUM"] or "",
                        now_playing_genre=row["Z_DKNOWPLAYINGMETADATAKEY__GENRE"] or "",
                        now_playing_duration=row["Z_DKNOWPLAYINGMETADATAKEY__DURATION"] or 0.0,
                        now_playing_is_playing=row["Z_DKNOWPLAYINGMETADATAKEY__PLAYING"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing media_usage at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Notifications (/notification/usage) ──────────────────────────────

    @export(record=KnowledgeCNotificationRecord)
    def notifications(self) -> Iterator[KnowledgeCNotificationRecord]:
        """Parse notification events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZVALUESTRING
                    FROM ZOBJECT WHERE ZSTREAMNAME = '/notification/usage'
                    ORDER BY ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCNotificationRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        bundle_id=row["ZVALUESTRING"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing notifications at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Intents (/app/intents) ───────────────────────────────────────────

    @export(record=KnowledgeCIntentRecord)
    def intents(self) -> Iterator[KnowledgeCIntentRecord]:
        """Parse app intent events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT o.ZSTARTDATE, o.ZENDDATE, o.ZCREATIONDATE, o.ZVALUESTRING,
                           s.ZBUNDLEID,
                           sm.Z_DKINTENTMETADATAKEY__INTENTCLASS,
                           sm.Z_DKINTENTMETADATAKEY__INTENTVERB,
                           sm.Z_DKINTENTMETADATAKEY__DIRECTION,
                           sm.Z_DKINTENTMETADATAKEY__INTENTHANDLINGSTATUS
                    FROM ZOBJECT o
                    LEFT JOIN ZSOURCE s ON o.ZSOURCE = s.Z_PK
                    LEFT JOIN ZSTRUCTUREDMETADATA sm ON o.ZSTRUCTUREDMETADATA = sm.Z_PK
                    WHERE o.ZSTREAMNAME = '/app/intents'
                    ORDER BY o.ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCIntentRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        intent_category=row["ZVALUESTRING"] or "",
                        source_bundle_id=row["ZBUNDLEID"] or "",
                        intent_class=row["Z_DKINTENTMETADATAKEY__INTENTCLASS"] or "",
                        intent_verb=row["Z_DKINTENTMETADATAKEY__INTENTVERB"] or "",
                        intent_direction=row["Z_DKINTENTMETADATAKEY__DIRECTION"] or 0,
                        intent_handling_status=row["Z_DKINTENTMETADATAKEY__INTENTHANDLINGSTATUS"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing intents at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Display (/display/isBacklit) ─────────────────────────────────────

    @export(record=KnowledgeCDisplayRecord)
    def display(self) -> Iterator[KnowledgeCDisplayRecord]:
        """Parse display backlight state from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZVALUEINTEGER
                    FROM ZOBJECT WHERE ZSTREAMNAME = '/display/isBacklit'
                    ORDER BY ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCDisplayRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        is_backlit=bool(row["ZVALUEINTEGER"]),
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing display at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Bluetooth (/bluetooth/isConnected) ───────────────────────────────

    @export(record=KnowledgeCBluetoothRecord)
    def bluetooth(self) -> Iterator[KnowledgeCBluetoothRecord]:
        """Parse bluetooth connection events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT o.ZSTARTDATE, o.ZENDDATE, o.ZCREATIONDATE, o.ZVALUEINTEGER,
                           sm.Z_DKBLUETOOTHMETADATAKEY__NAME,
                           sm.Z_DKBLUETOOTHMETADATAKEY__ADDRESS,
                           sm.Z_DKBLUETOOTHMETADATAKEY__DEVICETYPE,
                           sm.Z_DKBLUETOOTHMETADATAKEY__PRODUCTID
                    FROM ZOBJECT o
                    LEFT JOIN ZSTRUCTUREDMETADATA sm ON o.ZSTRUCTUREDMETADATA = sm.Z_PK
                    WHERE o.ZSTREAMNAME = '/bluetooth/isConnected'
                    ORDER BY o.ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCBluetoothRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        is_connected=bool(row["ZVALUEINTEGER"]),
                        device_name=row["Z_DKBLUETOOTHMETADATAKEY__NAME"] or "",
                        device_address=row["Z_DKBLUETOOTHMETADATAKEY__ADDRESS"] or "",
                        device_type=row["Z_DKBLUETOOTHMETADATAKEY__DEVICETYPE"] or 0,
                        product_id=row["Z_DKBLUETOOTHMETADATAKEY__PRODUCTID"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing bluetooth at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Discoverability (/discoverability/signals) ───────────────────────

    @export(record=KnowledgeCDiscoverabilityRecord)
    def discoverability(self) -> Iterator[KnowledgeCDiscoverabilityRecord]:
        """Parse discoverability signal events from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZSTARTDATE, ZENDDATE, ZCREATIONDATE, ZVALUESTRING
                    FROM ZOBJECT WHERE ZSTREAMNAME = '/discoverability/signals'
                    ORDER BY ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCDiscoverabilityRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        ts_created=_cocoa_ts(row["ZCREATIONDATE"]),
                        signal=row["ZVALUESTRING"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing discoverability at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Sync Peers (ZSYNCPEER table) ─────────────────────────────────────

    @export(record=KnowledgeCSyncPeerRecord)
    def sync_peers(self) -> Iterator[KnowledgeCSyncPeerRecord]:
        """Parse synced device peers from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZLASTSEENDATE, ZDEVICEID, ZMODEL, ZCLOUDID, ZVERSION
                    FROM ZSYNCPEER
                """)
                for row in cursor:
                    yield KnowledgeCSyncPeerRecord(
                        ts_last_seen=_cocoa_ts(row["ZLASTSEENDATE"]),
                        device_id=row["ZDEVICEID"] or "",
                        device_model=row["ZMODEL"] or "",
                        cloud_id=row["ZCLOUDID"] or "",
                        version=row["ZVERSION"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing sync_peers at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Sources (ZSOURCE table) ──────────────────────────────────────────

    @export(record=KnowledgeCSourceRecord)
    def sources(self) -> Iterator[KnowledgeCSourceRecord]:
        """Parse registered event sources from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZBUNDLEID, ZSOURCEID, ZDEVICEID, ZGROUPID, ZITEMID
                    FROM ZSOURCE
                """)
                for row in cursor:
                    yield KnowledgeCSourceRecord(
                        bundle_id=row["ZBUNDLEID"] or "",
                        source_id=row["ZSOURCEID"] or "",
                        device_id=row["ZDEVICEID"] or "",
                        group_id=row["ZGROUPID"] or "",
                        item_id=row["ZITEMID"] or "",
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing sources at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Histograms (ZHISTOGRAM + ZHISTOGRAMVALUE tables) ─────────────────

    @export(record=KnowledgeCHistogramRecord)
    def histograms(self) -> Iterator[KnowledgeCHistogramRecord]:
        """Parse activity level histograms from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT h.ZSTARTDATE, h.ZENDDATE, h.ZSTREAMNAME, h.ZIDENTIFIER,
                           h.ZDEVICEIDENTIFIER,
                           hv.Z_PK as BUCKET_ID, hv.ZHISTOGRAM as HISTOGRAM_ID,
                           hv.ZCOUNT
                    FROM ZHISTOGRAMVALUE hv
                    JOIN ZHISTOGRAM h ON hv.ZHISTOGRAM = h.Z_PK
                    ORDER BY h.ZSTARTDATE DESC
                """)
                for row in cursor:
                    yield KnowledgeCHistogramRecord(
                        ts_start=_cocoa_ts(row["ZSTARTDATE"]),
                        ts_end=_cocoa_ts(row["ZENDDATE"]),
                        stream_name=row["ZSTREAMNAME"] or "",
                        identifier=row["ZIDENTIFIER"] or "",
                        device_identifier=row["ZDEVICEIDENTIFIER"] or "",
                        bucket_id=row["BUCKET_ID"] or 0,
                        histogram_id=row["HISTOGRAM_ID"] or 0,
                        bucket_value=row["ZCOUNT"] or 0.0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing histograms at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()

    # ── Custom Metadata (ZCUSTOMMETADATA table) ──────────────────────────

    @export(record=KnowledgeCCustomMetadataRecord)
    def custom_metadata(self) -> Iterator[KnowledgeCCustomMetadataRecord]:
        """Parse custom metadata entries from knowledgeC.db."""
        for db_path, conn, tmp in self._iter_db():
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT ZNAME, ZSTRINGVALUE, ZINTEGERVALUE, ZDOUBLEVALUE,
                           ZDATEVALUE, ZOBJECT
                    FROM ZCUSTOMMETADATA
                    ORDER BY ZOBJECT
                """)
                for row in cursor:
                    yield KnowledgeCCustomMetadataRecord(
                        name=row["ZNAME"] or "",
                        string_value=row["ZSTRINGVALUE"] or "",
                        integer_value=row["ZINTEGERVALUE"] or 0,
                        double_value=row["ZDOUBLEVALUE"] or 0.0,
                        date_value=_cocoa_ts(row["ZDATEVALUE"]),
                        object_id=row["ZOBJECT"] or 0,
                        source=db_path,
                        _target=self.target,
                    )
            except Exception as e:
                self.target.log.warning("Error parsing custom_metadata at %s: %s", db_path, e)
            finally:
                conn.close()
                tmp.close()
