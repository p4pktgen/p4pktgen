import z3


class CustomExtern(object):
    """
    Extern object with apply function that performs a rshift by n bytes.
    Is deliberately written with generically named class and function as we
    expect to mainly have to have to deal with these cases.
    Arguments are passed into apply as a list to ensure that output arguments
    can be modified by the function.  Note that as program json does not specify
    which args are input/output the function must take care not to modify
    input entries in args.
    """
    def __init__(self, n):
        self.n = n

    def rshift_bv(self, input, start_output):
        assert z3.is_bv(input)
        assert z3.is_bv(start_output)
        assert input.size() == start_output.size()

        return input >> self.n

    def apply_fields(self, args):
        """
        Bitshifts a single field right by n.
        Expects two arguments, both z3 BitVecs of same sizes.
        """
        assert len(args) == 2
        input = args[0]
        start_output = args[1]

        output = self.rshift_bv(input, start_output)

        args[1] = output

    def apply_headers(self, args):
        """
        Bitshifts each field in a header right by n, with no carryover between
        fields.
        Expects two arguments, both lists of z3 BitVecs of same sizes.
        """
        input_list = args[0]
        start_output_list = args[1]

        assert isinstance(input_list, list)
        assert isinstance(start_output_list, list)
        assert len(input_list) == len(start_output_list)

        output = [self.rshift_bv(input, start_output)
                  for input, start_output in zip(input_list, start_output_list)]

        args[1] = output
