from dissect.target.plugins.apps.webservers.webservers import WebserverRecord

from dissect.target.plugins.apps.webservers.nginx import NginxPlugin
from ._utils import absolute_path


class TestNginx:
    def test_txt(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/nginx/access.log")
        fs_unix.map_file("var/log/nginx/access.log", data_file)
        target_unix.add_plugin(NginxPlugin)

        results = list(target_unix.nginx())
        assert len(results) == 2

        log: WebserverRecord = results[0]

        assert log.statuscode == 200
        assert log.ipaddr == "1.2.3.4"
        assert log.remote_user == "admin"

    def test_ipv6(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/nginx/access.log")
        fs_unix.map_file("var/log/nginx/access.log", data_file)
        target_unix.add_plugin(NginxPlugin)

        results = list(target_unix.nginx())
        assert len(results) == 2

        log: WebserverRecord = results[1]
        assert log.ipaddr == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_gz(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/nginx/access.log.gz")
        fs_unix.map_file("var/log/nginx/access.log.1.gz", data_file)
        target_unix.add_plugin(NginxPlugin)

        results = list(target_unix.nginx())
        assert len(results) == 2

        log: WebserverRecord = results[0]

        assert log.statuscode == 200
        assert log.ipaddr == "1.2.3.4"
        assert log.remote_user == "admin"

    def test_bz2(self, target_unix, fs_unix):
        data_file = absolute_path("data/webservers/nginx/access.log.bz2")
        fs_unix.map_file("var/log/nginx/access.log.1.bz2", data_file)
        target_unix.add_plugin(NginxPlugin)

        results = list(target_unix.nginx())
        assert len(results) == 2

        log: WebserverRecord = results[0]

        assert log.statuscode == 200
        assert log.ipaddr == "1.2.3.4"
        assert log.remote_user == "admin"
