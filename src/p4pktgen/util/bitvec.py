"""Utility wrappers around some Z3 bitvector functionality."""

import z3


def equalize_bv_size(*bvs):
    """Yields zero-extensions of the input bitvectors such that those
    extensions all have equal and minimal width.
    """
    target_size = max(bv.size() for bv in bvs)
    for bv in bvs:
        yield (z3.ZeroExt(target_size - bv.size(), bv)
               if bv.size() != target_size else bv)


def LShREq(val, shift):
    """Morally equivalent to z3.LShR, but zero-extends its arguments as
    necessary so that the shift is well-defined.
    """
    return z3.LShR(*equalize_bv_size(val, shift))
