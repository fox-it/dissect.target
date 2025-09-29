from dissect.target.plugins.hypervisor.hyperv import HyperVPlugin


def test_get_parent_hostname_windows(monkeypatch):
    class DummyResult:
        def __init__(self, stdout):
            self.stdout = stdout
    def fake_run(cmd, capture_output, text, check):
        return DummyResult("HYPERV-HOST\n")
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_run)
    plugin = HyperVPlugin(None)
    assert plugin.get_parent_hostname() == "HYPERV-HOST"


def test_get_parent_hostname_linux(monkeypatch, tmp_path):
    # Simulate Hyper-V DMI data
    dmi_dir = tmp_path / "sys/class/dmi/id"
    dmi_dir.mkdir(parents=True)
    (dmi_dir / "product_name").write_text("Microsoft Hyper-V")
    (dmi_dir / "sys_vendor").write_text("HYPERV-HOST")
    monkeypatch.setattr("pathlib.Path.read_text", lambda self: (dmi_dir / self.name).read_text())
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    plugin = HyperVPlugin(None)
    assert plugin.get_parent_hostname() == "HYPERV-HOST"


def test_get_parent_hostname_not_hyperv(monkeypatch, tmp_path):
    dmi_dir = tmp_path / "sys/class/dmi/id"
    dmi_dir.mkdir(parents=True)
    (dmi_dir / "product_name").write_text("KVM")
    monkeypatch.setattr("pathlib.Path.read_text", lambda self: (dmi_dir / self.name).read_text())
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Linux")
    plugin = HyperVPlugin(None)
    assert plugin.get_parent_hostname() is None
