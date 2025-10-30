import pytest
import zipfile
from pathlib import Path
from unittest.mock import Mock
from dissect.target.plugins.os.windows.cim import CimPlugin
from dissect.cim import cim


@pytest.fixture
def real_sample_cim(tmp_path):
    # Extract the zip containing INDEX.BTR, OBJECTS.DATA, MAPPING*.MAP
    test_data_folder = Path(__file__).parent.parent.parent.parent / "_data"
    zip_path = test_data_folder / "plugins" / "os" / "windows" / "cim" /  "not_default_namespace.zip"
    if not zip_path.exists():
        pytest.skip("Real sample zip not available")

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(tmp_path)
        # Debug: list extracted files
        extracted_files = list(tmp_path.rglob("*"))
        print(f"Extracted files: {[str(f.relative_to(tmp_path)) for f in extracted_files]}")

    return tmp_path


def test_consumerbindings_with_real_sample(real_sample_cim):
    repo = cim.CIM.from_directory(real_sample_cim)

    # Simple mock target
    target = Mock()
    target.resolve = Mock(return_value=Mock(exists=lambda: False))
    target.log = Mock()
    target._config = Mock(CACHE_DIR="/tmp")
    target.path = "/mock"
    target.hostname = "mock"
    target.domain = "mock"

    plugin = CimPlugin(target)
    plugin._repo = repo
    plugin._filters = plugin._get_filters()

    results = list(plugin.consumerbindings())
    binding_names = [r.filter_name for r in results]
    assert "Pentestlab-WMI" in binding_names


@pytest.fixture
def mock_target():
    target = Mock()
    target.resolve.return_value.exists.return_value = True
    target.resolve.return_value.joinpath.return_value.open.return_value = Mock()
    return target


@pytest.fixture
def mock_cim_repo():
    # Mock the CIM repo
    repo = Mock()
    root = Mock()
    repo.root = root

    # Create mock namespaces
    ns1 = Mock()
    ns1.name = "root\\subscription"
    ns2 = Mock()
    ns2.name = "root\\other"

    # Mock classes and instances for ns1 (subscription)
    binding_class1 = Mock()
    binding_instance1 = Mock()
    binding_instance1.properties = {"Consumer": Mock(value="consumer1"), "Filter": Mock(value="filter1")}
    binding_class1.instances = [binding_instance1]

    filter_class1 = Mock()
    filter_instance1 = Mock()
    filter_instance1.properties = {
        "Name": Mock(value="filter1"),
        "Query": Mock(value="SELECT * FROM __InstanceCreationEvent"),
        "QueryLanguage": Mock(value="WQL"),
        "CreatorSID": Mock(value=b"sid1")
    }
    filter_class1.instances = [filter_instance1]

    consumer_instance1 = Mock()
    consumer_instance1.properties = {"CommandLineTemplate": Mock(value="cmd.exe")}

    ns1.class_.side_effect = lambda name: {
        "__filtertoconsumerbinding": binding_class1,
        "__EventFilter": filter_class1
    }.get(name, Mock(instances=[]))
    ns1.query.return_value = consumer_instance1

    # For ns2, no instances
    ns2.class_.return_value.instances = []
    ns2.query.side_effect = Exception("No such class")

    root.namespaces = [ns1, ns2]

    return repo


def test_consumerbindings_all_namespaces(mock_target, mock_cim_repo):
    # Mock the CIM import
    import dissect.target.plugins.os.windows.cim as cim_module
    cim_module.cim.CIM = Mock(return_value=mock_cim_repo)

    # Create plugin
    plugin = CimPlugin(mock_target)

    # Mock the repo opening
    plugin._repo = mock_cim_repo

    # Call _iter_consumerbindings directly to avoid record issues
    bindings = list(plugin._iter_consumerbindings())

    # Verify it found the binding from ns1
    assert len(bindings) == 1
    consumer, filter_name = bindings[0]
    assert consumer.properties["CommandLineTemplate"].value == "cmd.exe"
    assert filter_name == "filter1"

    # Verify it tried both namespaces
    assert mock_cim_repo.root.namespaces[0].class_.call_count >= 1  # binding
    assert mock_cim_repo.root.namespaces[1].class_.call_count >= 1  # at least binding


def test_get_filters_all_namespaces(mock_target, mock_cim_repo):
    import dissect.target.plugins.os.windows.cim as cim_module
    cim_module.cim.CIM = Mock(return_value=mock_cim_repo)

    plugin = CimPlugin(mock_target)
    plugin._repo = mock_cim_repo

    filters = plugin._get_filters()

    assert "filter1" in filters
    assert filters["filter1"].filter_name == "filter1"
