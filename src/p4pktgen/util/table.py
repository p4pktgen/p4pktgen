class Table:
    def __init__(self):
        self.data = []

    def add_rows(self, rows):
        self.data += rows

    def __str__(self):
        max_lens = []
        for row in self.data:
            for i, cell in enumerate(row):
                assert i <= len(max_lens)

                if i == len(max_lens):
                    max_lens.append(0)
                max_lens[i] = max(len(cell), max_lens[i])

        row_format = '\t' + ''.join(
            ['{:>' + str(max_len + 1) + '}' for max_len in max_lens]) + '\n'
        result = ''
        for row in self.data:
            if len(row) < len(max_lens):
                row += [''] * (len(max_lens) - len(row))
            result += row_format.format(*row)
        return result
