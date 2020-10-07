class Path(object):
    def __init__(self, id, expected_path, parser_path, control_path, is_complete):
        self.id = id
        self.expected_path = expected_path
        self.parser_path = parser_path
        self.control_path = control_path
        self.is_complete = is_complete

    def __str__(self):
        return "%d Exp path (len %d+%d=%d) complete_path %s: %s" % (
            self.id, len(self.parser_path), len(self.control_path),
            len(self.parser_path) + len(self.control_path),
            self.is_complete, self.expected_path
        )
