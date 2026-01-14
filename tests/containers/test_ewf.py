from dissect.target import container
from dissect.target.containers.ewf import EwfContainer
from tests._utils import absolute_path


def test_ewf_container() -> None:
    path = absolute_path("_data/containers/ewf/small.E01")

    fh = container.open(path)
    assert isinstance(fh, EwfContainer)
    a = fh.read(20)
    assert a == b"testdissecte01\n"
