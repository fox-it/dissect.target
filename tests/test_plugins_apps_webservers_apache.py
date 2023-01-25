from datetime import datetime, timezone
from io import BytesIO

from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

from dissect.target.plugins.apps.webservers.apache import ApachePlugin, infer_log_format
from ._utils import absolute_path


class TestHelpers:
    def test_infer_log_format_combined(self):
        log_combined = (
            '127.0.0.1 - - [19/Dec/2022:17:25:12 +0100] "GET / HTTP/1.1" 304 247 "-" "Mozilla/5.0 '
            "(Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 "
            'Safari/537.36"'
        )
        assert infer_log_format(log_combined) == "combined"

    def test_infer_log_format_vhost_combined(self):
        log_vhost_combined = (
            'example.com:80 127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312 '
            '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/108.0.0.0 Safari/537.36"'
        )
        assert infer_log_format(log_vhost_combined) == "vhost_combined"

    def test_infer_log_format_common(self):
        log_common = '127.0.0.1 - - [19/Dec/2022:17:25:40 +0100] "GET / HTTP/1.1" 200 312'
        assert infer_log_format(log_common) == "common"

    def test_infer_log_ipv6(self):
        log_common = (
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334 - - [20/Dec/2022:15:18:01 +0100] "GET / HTTP/1.1" 200 '
            '1126 "-" "curl/7.81.0"'
        )
        assert infer_log_format(log_common) == "combined"


class TestApache:
    def test_txt(self, target_unix_users, fs_unix):
        data_file = absolute_path("data/webservers/apache/access.log")
        fs_unix.map_file("var/log/apache2/access.log", data_file)
        target_unix_users.add_plugin(ApachePlugin)

        results = list(target_unix_users.apache())
        assert len(results) == 4

    def test_gz(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/apache/access.log.gz")
        fs_unix.map_file("var/log/apache2/access.log.1.gz", data_file)
        target_unix.add_plugin(ApachePlugin)

        results = list(target_unix.apache())
        assert len(results) == 4

    def test_bz2(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/apache/access.log.bz2")
        fs_unix.map_file("var/log/apache2/access.log.1.bz2", data_file)
        target_unix.add_plugin(ApachePlugin)

        results = list(target_unix.apache())
        assert len(results) == 4

    def test_all_log_formats(self, target_unix, fs_unix):
        fs_unix.map_file_fh("/etc/timezone", BytesIO("Etc/UTC".encode()))
        data_file = absolute_path("data/webservers/apache/access.log")
        fs_unix.map_file("var/log/apache2/access.log", data_file)
        target_unix.add_plugin(ApachePlugin)

        results = list(target_unix.apache())
        assert len(results) == 4

        combined_log: WebserverRecord = results[0]
        assert combined_log.ts == datetime(2022, 12, 19, 17, 6, 19, tzinfo=timezone.utc)
        assert combined_log.statuscode == 200
        assert combined_log.ipaddr == "1.2.3.4"
        assert combined_log.remote_user == "-"
        assert combined_log.url == "GET / HTTP/1.1"
        assert combined_log.referer == "Sample referer"
        assert (
            combined_log.useragent
            == "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 "
            "Safari/537.36"
        )

        vhost_combined_log: WebserverRecord = results[1]
        assert vhost_combined_log.ts == datetime(2022, 12, 19, 17, 25, 40, tzinfo=timezone.utc)
        assert vhost_combined_log.statuscode == 200
        assert vhost_combined_log.ipaddr == "1.2.3.4"
        assert vhost_combined_log.remote_user == "-"
        assert vhost_combined_log.url == "GET /index.html HTTP/1.1"
        assert vhost_combined_log.referer == "-"
        assert (
            vhost_combined_log.useragent
            == "Mozilla/5.0 (Windows NT 10.0; Win64; x64); AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 "
            "Safari/537.36"
        )

        common_log: WebserverRecord = results[2]
        assert common_log.ts == datetime(2022, 12, 19, 17, 25, 48, tzinfo=timezone.utc)
        assert common_log.statuscode == 200
        assert common_log.ipaddr == "4.3.2.1"
        assert common_log.remote_user == "-"
        assert common_log.url == "GET / HTTP/1.1"
        assert common_log.referer is None
        assert common_log.useragent is None

        ipv6_log: WebserverRecord = results[3]
        assert ipv6_log.ipaddr == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
