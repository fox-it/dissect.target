rule test_rule_name : tag1 tag2 tag3 {
    meta:
        foo = "bar"

    strings:
        $ = "test string" // some comment

    condition:
        any of them
}