from dissect.target.plugin import Plugin, export


class TestPlugin(Plugin):
    def check_compatible(self) -> None:
        return None

    @export(output="default")
    def hello_world(self):
        for x in self.target.fs.iterdir(""):
            print(f"hello {x}")
