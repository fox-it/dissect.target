rule test_rule_name {
    strings:
        $ = "test string"

    condition:
        any of them
}