= Notes on Z3 SMT solver

== Unusual model values for some variables without 'significant' constraints

Unusual thing about the Z3 solver.  If a variable has no 'interesting'
constraints on it, you can solve them, but the model comes back with a
value that when printed looks like the name of the variable, not a
value of the type/kind.  It does not appear to be the identical Python
object, according to the `is` tests below returning `False`, but it
appears to be the same type from the fact that the values returned by
`type()` and `dir()` for both objects are equal according to `==`.

An example:

```python
% source my-venv/bin/active
% python
[23:11:52] $ python
Python 2.7.12 (default, Nov 20 2017, 18:23:56) 
[GCC 5.4.0 20160609] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from z3 import *
>>> x=BitVec('x', 32)
>>> s=Solver()
>>> s.add(x==x)
>>> s.check()
sat
>>> s.model().eval(x)
x
>>> from z3 import *
>>> x=BitVec('x',32)
>>> s=Solver()
>>> s.add(x==x)
>>> s.check()
sat
>>> s.model().eval(x)
x
>>> s.model().eval(x) is x
False
>>> x is s.model().eval(x)
False
>>> dir(x) == dir(s.model().eval(x))
True
>>> type(x) == type(s.model().eval(x))
True
```

If I create a second variable of the same kind and a constraint making
them equal, they both come out 0:

```python
>>> from z3 import *
>>> x=BitVec('x',32)
>>> y=BitVec('y',32)
>>> s=Solver()
>>> s.add(x==y)
>>> s.check()
sat
>>> s.model().eval(x)
0
>>> s.model().eval(y)
0
```

Not clear if this is intentional behavior on the part of Z3, or a bug.
