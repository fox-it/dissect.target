rule another_rule {
    strings:
        $ = "test"

    condition:
        any of them
}